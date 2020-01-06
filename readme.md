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

| verb   | path               | input         | output       |
|--------|--------------------|---------------|--------------|
| `GET`  | `/api/pki/ca`      |               | `CERT-CHAIN` |
| `POST` | `/api/pki/keypair` | `KEYQUERY`    | `KEYPAIR`    |
| `POST` | `/api/pki/csr`     | `CSRQUERY`    | `CSR`        |
| `POST` | `/api/pki/_sign`   | `CSR`         | `CERT-CHAIN` |
| `POST` | `/api/pki/cert`    | `CSRCSRQUERY` | `CERT-CHAIN` |

`CSRCSRQUERY` format

```json
{
  "hosts" : [ "www.foo.bar", "www2.foo.bar" ],
  "key" : {
    "algo" : "rsa",
    "size" : 2048
  },
  "client": false,  // optional
  "subject": "...", // optional
  "name" : {        // optional
    "C" : "foo",
    "OU" : "bar"
  },
  "signatureAlg" : "SHA256WithRSAEncryption",
  "digestAlg" : "SHA-256"
}
```

`KEYQUERY` format

```json
{
  "algo" : "rsa",
  "size" : 2048
}
```

## Try

```sh
curl -k -X GET https://pki.oto.tools:8443/api/pki/ca

curl -k -X GET -H 'Accept: application/x-pem-file' https://pki.oto.tools:8443/api/pki/ca

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

curl -k -X POST -H 'Content-Type: application/json' -H 'Accept: application/x-pem-file' https://pki.oto.tools:8443/api/pki/cert -d '
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