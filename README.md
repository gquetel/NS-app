# NS-app
Research project application in Network Security aiming to fingerprint ClientHello from TLS Clients connection to the created server.

To also verify that connected client properly does certificate verification, we created subdomaines corresponding to different cases: 

| Subdomain    | Corresponding case             | Should be reached by client ? |
|--------------|--------------------------------|-------------------------------|
| sub1         | Certificate outdated/incorrect | No                            |
| sub2         | Self-signed certificate        | No                            |
| sub3         | Wildcard certificate           | Yes                           |
| sub.sub3     | Wildcard certificate           | No                            |
| sub.sub.sub3 | Wildcard certificate           | No                            |


This application has been build using the [https://tlslite-ng.readthedocs.io/en/latest/](tlslite-ng) package and by modifying to keep track of the sent ClientHello.

Here are the available routes that you can reach with this application:

| Route         | Content                                                              |
|---------------|----------------------------------------------------------------------|
| `/`           | Default webpage, shows your TLS fingerprint, not recommended cipher. |
| `/fp`         | Display hash of 10 last fingerprints                                 |
| `user-agents` | Display user-agents of 10 last fingerprints                          |
| `/api`        | Server JSON of your fingerprint                                      |


## Prerequisites

#### Required packages: 
- `pandas`
- `pymongo`
- `tlslite-ng`

To make this application work you need to have the certificate and the private key corresponding to your domain name (`cert.pem`, `key.pem`)  in a `./certs/` folder. 

## Install

Generating certificates

```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.pem -out certificate.pem
```

