# pki-tools

a simple REST API to generate KeyPairs, CSR and Certificates based on a CA certificate and private key

## Build and run

```sh
sbt assembly
mv ./target/scala-2.12/pki-tools.jar ./pki-tools.jar
java -Dpki.ca=/path/to/ca.pem, -Dpki.caKey=/path/to/ca-key.pem -jar pki-tools.jar
```

## Run in dev mode

```sh
sbt run --- -Dpki.ca=/path/to/ca.pem, -Dpki.caKey=/path/to/ca-key.pem
```

## API

```
GET    --       /api/pki/ca
POST   CSR      /api/pki/cert
POST   CSR      /api/pki/csr
POST   KEY      /api/pki/keypair
POST   CSRPEM   /api/pki/_sign
```

`CSR` format

```json
{
  "hosts" : [ ... ],
  "key" : {
    "algo" : "rsa",
    "size" : 2048
  },
  "name" : {
    "C" : "foo",
    "OU" : "bar"
  },
  "signatureAlg" : "SHA256WithRSAEncryption",
  "digestAlg" : "SHA-256"
}
```

`KEY` format

```json
{
  "algo" : "rsa",
  "size" : 2048
}
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