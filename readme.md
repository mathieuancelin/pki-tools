# pki-tools

a simple REST API to generate KeyPairs, CSR and Certificates based on a CA certificate and private key

## Run

```sh
sbt run -Dpki.ca=/path/to/ca.pem, -Dpki.caKey=/path/to/ca-key.pem
```

## Try

```sh
curl -k -X GET https://pki.oto.tools:8443/api/pki/ca

curl -k -X GET -H 'Accept: text/plain' https://pki.oto.tools:8443/api/pki/ca

curl -k -X POST -H 'Content-Type: application/json' https://pki.oto.tools:8443/api/pki/cert -d '
{
  "hosts" : [ "domain1.oto.tools", "domain2.oto.tools", "domain3.oto.tools" ],
  "key" : {
    "algo" : "rsa",
    "size" : 2048
  },
  "name" : {
    "C" : "FR",
    "L" : "Poitiers",
    "O" : "OtoroshiLabs",
    "OU" : "Test"
  },
  "signatureAlg" : "SHA256WithRSAEncryption",
  "digestAlg" : "SHA-256"
}'

curl -k -X POST -H 'Content-Type: application/json' -H 'Accept: text/plain' https://pki.oto.tools:8443/api/pki/cert -d '
{
  "hosts" : [ "domain1.oto.tools", "domain2.oto.tools", "domain3.oto.tools" ],
  "key" : {
    "algo" : "rsa",
    "size" : 2048
  },
  "name" : {
    "C" : "FR",
    "L" : "Poitiers",
    "O" : "OtoroshiLabs",
    "OU" : "Test"
  },
  "signatureAlg" : "SHA256WithRSAEncryption",
  "digestAlg" : "SHA-256"
}'
```