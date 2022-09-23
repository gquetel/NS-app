# NS-app
Research project application in Network Security

## Prerequisites

Certificates (`cert.pem`, `key.pem`) must be present in a `./certs/` folder. 

## Install

Generating certificates

```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.pem -out certificate.pem
```

