import argparse
import json
import sys
import hashlib
import re
import os
import database_connect


# My custom tls_connection class, modified to keep track of clientHello
import my_tlsconnection
import handshake
import parameter_iana_loader


from tlslite import *
from tlslite.constants import *
from tlslite.errors import *


ADDRESS = "0.0.0.0"
PORT = 443
MONGO_URI = ""

db_connection = None


def mapVersion(version):
    """Function to map value given by the protocol version tuple given
    by the client Hello to a human readable value."""
    if version == (3, 0):
        return "SSL 3.0"
    elif version == (3, 1):
        return "TLS 1.0"
    elif version == (3, 2):
        return "TLS 1.1"
    elif version == (3, 3):
        return "TLS 1.2"
    elif version == (3, 4):
        return "TLS 1.3"
    else:
        return None


def mapSignatureScheme(signature_byte_array):
    """ Function to map value given by the signature_algorithm field"""

    sign_hexvalue = []
    for i in range(len(signature_byte_array), 2):
        sign_hexvalue.append(int.from_bytes(
            [signature_byte_array[i], signature_byte_array[i+1]], byteorder='big'))

    # Then we map them to our df_signature to get a proper name
    ret = []
    for client_signature in sign_hexvalue:
        try:
            value = set_signatures[client_signature]
            ret.append(value)
        except KeyError:
            pass

    return ret


def mapCiphers(cipher_list):
    """Function to map value given by clientHello in cipher suites to human
    readable values. """

    ret = []
    weak_cipher = []

    for client_cipher in cipher_list:
        try:
            value = set_cipher[client_cipher]["cipher"]
            ret.append(value)

            if(not set_cipher[client_cipher]["recommended"]):
                weak_cipher.append(value)

        except KeyError:
            pass
    return (ret, weak_cipher)


def mapGroups(group_list):
    """Function to map value given by clientHello in supported group to human
    readable values. """

    ret = []
    for client_group in group_list:
        try:
            value = set_groups[client_group]
            ret.append(value)
        except KeyError:
            pass
    return ret


def server():

    # Setting up the HTTPS server
    address = (ADDRESS, int(PORT))
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(address)
    lsock.listen(5)

    def connect():
        s = lsock.accept()[0]
        s.settimeout(15)
        return (my_tlsconnection.TLSConnection(s), s)

    try:
        # Start the TLS connection
        connection, s = connect()
        handshake.do_handshake(connection)
        clientHello = connection.clientHello

        # Routing
        req = connection.recv(1024).decode('utf-8')
        req = req.split('\n')
        path = req[0].split(' ')[1]
        user_agent = None
        sub = clientHello.server_name.decode()

        for header in req:
            if re.match("User-Agent:", header):
                user_agent = header.rstrip()
                break

        if(not user_agent):
            connection.send(
                'HTTP/1.1 200 OK\nContent-Type: text/html\n\n'.encode())
            connection.send("Couldn't retriver your user-agent".encode())
            return

        # GET /src/img/favicon.png serve favicon of webpage
        if re.match("/img/favicon.ico", path):
            f = open("src/img/favicon.ico", 'rb')
            connection.send(
                'HTTP/1.1 200 OK\nContent-Type: image/png\n\n'.encode())
            connection.send(f.read())
            f.close()
            connection.close()
            return

        # GET /src/img/logo.png serve cyberschool logo
        elif re.match("/src/img/logo.png", path):
            f = open("src/img/logo.png", 'rb')
            connection.send(
                'HTTP/1.1 200 OK\nContent-Type: image/png\n\n'.encode())
            connection.send(f.read())
            f.close()
            connection.close()
            return

         # GET sub*.ns-rt.tk/*
        if (re.match("sub*", sub)):
            if (re.match("sub1", sub)):
                f = open("src/js/sub1.js", 'rb')
            elif (re.match("sub2", sub)):
                f = open("src/js/sub2.js", 'rb')
            elif (re.match("sub3", sub)):
                f = open("src/js/sub3.js", 'rb')
            elif (re.match("sub.sub3", sub)):
                f = open("src/js/ssub3.js", 'rb')
            elif (re.match("sub.sub.sub3", sub)):
                f = open("src/js/sssub3.js", 'rb')
            connection.send(
                'HTTP/1.1 200 OK\nContent-Type: text/javascript\n\n'.encode())
            connection.send(f.read())
            f.close()
            connection.close()
            return

        cipher_suites, weak_ciphers = mapCiphers(clientHello.cipher_suites)

        # Sort keys must be set to true so we get the same hash out of 2 same request
        string_fg = json.dumps({
            'cipher_suites': cipher_suites,
            'client_version': mapVersion(clientHello.client_version),
            'compression_methods': clientHello.compression_methods,
            'ec_point_format': clientHello.getExtension(ExtensionType.ec_point_formats).formats,
            'supported_groups': mapGroups(clientHello.getExtension(ExtensionType.supported_groups).groups),
            'signature_scheme_algorithm': mapSignatureScheme(clientHello.getExtension(ExtensionType.signature_algorithms).extData)
        }, sort_keys=True)

        # Generate sha out of fp, and save data to db now we send the data to the database
        sha_fp = hashlib.sha384(string_fg.encode()).hexdigest()
        json_fp = json.loads(string_fg)
        json_data = json.dumps({
            'tls_fingerprints': json_fp,
            'user-agent': user_agent,
            'ip_address': s.getpeername()[0],
            'sha_384': sha_fp,
            'weak_ciphers': weak_ciphers
        }, sort_keys=True)

        json_without_ip = json.dumps({
            'tls_fingerprints': json_fp,
            'user-agent': user_agent,
            'sha_384': sha_fp,
        }, sort_keys=True)

        # GET /api/ and server result in json
        if re.match("^(/api|/api/)$", path):
            connection.send(
                'HTTP/1.1 200 OK\nContent-Type: application/json\n\n'.encode())
            connection.send(json_data.encode())
            connection.close()

            # Save fingerprints to database
            db_connection.save_client_hello(json.loads(json_without_ip))
            return

        # GET /fp/ and get the 10 last fingerprints in the database
        elif re.match("^(/fp|/fp/|/fp\?)$", path):
            connection.send(
                'HTTP/1.1 200 OK\nContent-Type: application/json\n\n'.encode())
            connection.send(db_connection.get_fp().encode())
            connection.close()
            return


        # GET /.* print default webpage
        elif re.match("/$", path):

            weak_ciphers_string = json.dumps({
                'weak_ciphers': weak_ciphers
            })
            connection.send(
             'HTTP/1.1 200 OK\nContent-Type: text/html\n\n'.encode())
            connection.send("""
            <!DOCTYPE html>
            <head>
                <link rel="icon" type="image/x-icon" href="/img/favicon.ico">
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>Networks Security - Research Project</title>
                <script>
                    var res_sub1 = false;
                    var res_sub2 = false;
                    var res_sub3 = false;
                    var res_ssub3 = false;
                    var res_sssub3 = false;
                    var res_sub4 = false;
                    var res_sub5 = false;
                    var res_sub6 = false;
                </script>
            </head>
            <body>
                <div style="text-align:center; padding-top:3em;">
                    <img src="src/img/logo.png" width="450">
                    <h1 style="padding-top:1em">The Security Impact of HTTPS Interception</h1>
                    <h2>Networks Security - Research Project</h2>
                    <div style="width:100%">
                            <pre id="warnings"></pre>
                            <h2 style="text-align:left;"> About your TLS configuration:<br> </h2>
                            <pre style="text-align:left;" id="json_fp"></pre>
                    </div>

                    <h2 style="text-align:left;"> Not recommended advertised ciphers </h2>
                    <div style="text-align:left;">
                    If an item is not marked as "Recommended", it does not
                    necessarily mean that it is flawed; rather, it indicates that
                    the item either has not been through the IETF consensus process,
                    has limited applicability, or is intended only for specific use
                    cases.
                    </div>
                    <pre style="text-align:left;" id="json_weak"></pre>

                <table>

                    <style>
                        table, td {
                            border: 1px solid #333;
                            align: center;
                        }
                        table {
                            margin-left: auto;
                            margin-right: auto;
                        }
                        thead, tfoot {
                            background-color: #333;
                            color: #fff;
                        }
                    </style>
                    <thead>
                        <tr>
                            <th colspan="1">Subdomains</th>
                            <th colspan="1">RFC</th>
                            <th colspan="1">Tests</th>
                            <th colspan="1">Should be reached ?</th>
                            <th colspan="1">Reached</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Sub1</td>
                            <td><a href="https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2">RFC 5246</a></td>
                            <td>Invalid Cert.</td>
                            <td>NO</td>
                            <td id="sub1">
                                <script src="https://sub1.tls.gquetel.fr/sub1.js"></script>
                                <script>
                                    if (res_sub1) { document.getElementById('sub1').innerHTML = "<strong style='color: red'>YES</strong>"; }
                                    else { document.getElementById('sub1').innerHTML = "<strong style='color: green'>NO</strong>"; }
                                </script>
                            </td>
                        </tr>
                        <tr>
                            <td>Sub 2</td>
                            <td><a href="https://www.ietf.org/rfc/rfc3280.txt">RFC 3280</a></td>
                            <td>Self-Signed Cert.</td>
                            <td>NO</td>
                            <td id="sub2">
                                <script src="https://sub2.tls.gquetel.fr/sub2.js"></script>
                                <script> if (res_sub2) { document.getElementById('sub2').innerHTML = "<strong style='color: red'>YES</strong>"; }
                                            else { document.getElementById('sub2').innerHTML = "<strong style='color: green'>NO</strong>"; }
                                </script>
                            </td>
                        </tr>
                        <tr>
                            <td>Sub 3</td>
                            <td><a href="https://datatracker.ietf.org/doc/html/rfc4592">RFC 4592</a></td>
                            <td>Wildcard</td>
                            <td>YES</td>
                            <td id="sub3">
                                <script src="https://sub3.tls.gquetel.fr/sub3.js"></script>
                                <script> if (res_sub3) { document.getElementById('sub3').innerHTML = "<strong style='color: green'>YES</strong>"; }
                                            else { document.getElementById('sub3').innerHTML = "<strong style='color: red'>NO</strong>"; }
                                </script>
                            </td>
                        </tr>
                        <tr>
                            <td>Sub Sub3</td>
                            <td><a href="https://datatracker.ietf.org/doc/html/rfc4592">RFC 4592</a></td>
                            <td>Wildcard</td>
                            <td>NO</td>
                            <td id="ssub3">
                                <script src="https://sub.sub3.tls.gquetel.fr/ssub3.js"></script>
                                <script> if (res_ssub3) { document.getElementById('ssub3').innerHTML = "<strong style='color: red'>YES</strong>"; }
                                            else { document.getElementById('ssub3').innerHTML = "<strong style='color: green'>NO</strong>"; }
                                </script>
                            </td>
                        </tr>
                        <tr>
                            <td>Sub Sub Sub3</td>
                            <td><a href="https://datatracker.ietf.org/doc/html/rfc4592">RFC 4592</a></td>
                            <td>Wildcard</td>
                            <td>NO</td>
                            <td id="sssub3">
                                <script src="https://sub.sub.sub3.tls.gquetel.fr/sssub3.js"></script>
                                <script> if (res_sssub3) { document.getElementById('sssub3').innerHTML = "<strong style='color: red'>YES</strong>"; }
                                            else { document.getElementById('sssub3').innerHTML = "<strong style='color: green'>NO</strong>"; }
                                </script>
                            </td>
                        </tr>
                    </tbody>
                </table>
                </div>
                <script>
                var data = """.encode())

            connection.send(json_data.encode())
            connection.send("""
                var data_weak = """.encode())
            connection.send(weak_ciphers_string.encode())
            connection.send("""
                document.getElementById("json_fp").innerHTML = JSON.stringify(data, undefined, 2);
                document.getElementById("json_weak").innerHTML = JSON.stringify(data_weak, undefined, 2);

                </script>

                </body>

              <footer style="">
                <div style="text-align:left; float:left; width:33%">Referent teacher: GOESSENS Mathieu</div>
                <div style="text-align:center; float:left; width:33%">DEMOLINIS Rémy, GASSINE Alan, QUETEL Grégor, THAY Jacky</div>
                <div style="float:right; width:10%"><form action="https://tls.gquetel.fr/fp"><input type="submit" value="See 10 last fingerprints"/></form></div>
            </footer>""".encode())
            connection.close()
            db_connection.save_client_hello(json.loads(json_without_ip))
            connection.close()
            return

    except TLSLocalAlert as e:
        print("TLSLocalAlert : ", e, file=sys.stderr)

    except TLSRemoteAlert as e:
        print("TLSRemoteAlert : ", e, file=sys.stderr)

    except TLSAbruptCloseError as e:
        print("TLSAbruptCloseError : ", e, file=sys.stderr)

    except Exception as e:
        print("Exception: ", e, file=sys.stderr)


if __name__ == "__main__":

    # Parsing of arguments and options
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", "-a",
                        help="specify the address to bind the socket to.", type=str)
    parser.add_argument("--local", "-l",
                        help="use local csv file instead of fetching them online.",
                        action="store_true")
    parser.add_argument("--port", "-p",
                        help="""specify the source port the application should use,
                        subject to privilege re‐strictions and availability.""", type=int)
    parser.add_argument("--mongouri", "-m",
                        help="""specify the mongodb uri to use to store collected tls-data.""")
    parser.add_argument("--verbose", "-v", help="display some more information about the server.",
                        action="store_true")

    args = parser.parse_args()

    fetch_local_csv = args.local
    verbose = args.verbose

    if(args.port):
        if(args.port >= 0 and args.port <= 65535):
            PORT = args.port
        else:
            parser.error("Please select a valid port [0,65535].")

    if(args.address):
        ADDRESS = args.address

    if(args.mongouri):
        MONGOURI = args.mongouri
    else:
        MONGOURI = os.getenv('MONGOURI')
        if(not MONGOURI):
            parser.error(
                "No mongouri argument were passed and environement variable MONGOURI not set, please provide one.")

    # Load dict of extensions values and their human readable description.
    set_cipher = parameter_iana_loader.get_cipher_dict(fetch_local_csv)
    if(set_cipher and verbose):
        print("parameter_iana_loader: CIPHER_SUITE dict loaded.")

    set_signatures = parameter_iana_loader.get_signature_dict(fetch_local_csv)
    if(set_signatures and verbose):
        print("parameter_iana_loader: SIGNATURE_SCHEME dict loaded.")

    set_groups = parameter_iana_loader.get_group_dict(fetch_local_csv)
    if(set_groups and verbose):
        print("parameter_iana_loader: SUPPORTED_GROUP dict loaded.")

    db_connection = database_connect.mongo_middleware(MONGOURI)

    print("Server up and running: https://", ADDRESS, ":", PORT, sep="")

    while True:
        server()
