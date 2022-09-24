from tlslite import *
from tlslite.handshakesettings import HandshakeSettings, VirtualHost, Keypair

"""
    Deals with the TLS handshake, future use could involve VirtualHost
"""

# No subdomain => tls.gquetel.fr
s = open("./certs/cert.pem").read()
x509_base = X509()
x509_base.parse(s)
s = open("./certs/cert.key").read()
privateKey_base = parsePEMKey(s, private=True)
certChain_base = X509CertChain([x509_base])
v_host_base = VirtualHost()
v_host_base.keys = [Keypair(x509_base, certChain_base.x509List)]
v_host_base.hostnames = [b"localhost", b"tls.gquetel.fr"]


# Subdomain1, no certificate => sub1.domainname
f = open("./certs/sub1/cert.pem").read()
x509_sub1 = X509()
x509_sub1.parse(f)
f = open("./certs/sub1/cert.key").read()
privateKey_sub1 = parsePEMKey(s, private=True)
certChain_sub1 = X509CertChain([x509_sub1])
v_host_sub1 = VirtualHost()
v_host_sub1.keys = [Keypair(privateKey_sub1, certChain_sub1.x509List)]
v_host_sub1.hostnames = [b"sub1.tls.gquetel.fr"]



# Subdomain2, self-signed cert => sub2.domainname
s = open("./certs/sub2/cert.pem").read()
x509_sub2 = X509()
x509_sub2.parse(s)
s = open("./certs/sub2/cert.key").read()
privateKey_sub2 = parsePEMKey(s, private=True)
certChain_sub2 = X509CertChain([x509_sub2])
v_host_sub2 = VirtualHost()
v_host_sub2.keys = [Keypair(privateKey_sub2, certChain_sub2.x509List)]
v_host_sub2.hostnames = [b"sub2.tls.gquetel.fr"]


# Subdomain3, wildcart cert => *.sub3.domainname
s = open("./certs/sub3/cert.pem").read()
x509_sub3 = X509()
x509_sub3.parse(s)
s = open("./certs/sub3/cert.key").read()
privateKey_sub3 = parsePEMKey(s, private=True)
certChain_sub3 = X509CertChain([x509_sub3])
v_host_sub3 = VirtualHost()
v_host_sub3.keys = [Keypair(privateKey_sub3, certChain_sub3.x509List)]
v_host_sub3.hostnames = [b'sub3.tls.gquetel.fr', b'sub.sub3.tls.gquetel.fr', b'sub.sub.sub3.tls.gquetel.fr']


def do_handshake(connection):
    settings = HandshakeSettings()
    settings.virtual_hosts = [v_host_sub1, v_host_sub2, v_host_sub3]

    connection.my_handshakeServer(
        privateKey=privateKey_base,
        certChain=certChain_base,
        settings=settings)
