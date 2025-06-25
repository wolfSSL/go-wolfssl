## Building the TLS Server/Client example

A simple TLS 1.2 server/client demonstration. The example `.go` files are located in the `client` and `server` directories.

To build the server, run :
```
go build server.go
```

To build the client, run :
```
go build client.go
```

**NOTE**: Make sure to run both the server and client from within their directories or change the certificate and key paths in the code so that the files are found.

## Building the DTLS Server/Client example

A simple DTLS 1.2 server/client demonstration. The example `.go` files are located in the `client` and `server` directories.

To build the server, run :
```
go build server-dtls.go
```

To build the client, run :
```
go build client-dtls.go
```

## Building the PSK TLS Server/Client example

A simple TLS 1.3 PSK server/client demonstration. The example `.go` files are located in the `client` and `server` directories.

To build the server, run :
```
go build server-psk.go
```

To build the client, run :
```
go build client-psk.go
```


## Building the AES encryption example

An application using wolfCrypt AES to encrypt/decrypt files. Located in `aes-encypt` directory.

To build the app, run :
```
go build aes-encypt.go
```

The usage is as shown below.
```
./aes-encrypt <infile name> <outfile name> <enc/dec> <key size>
```

## Building the hash example

An application to hash input files with the chosen algorithm. Located in `hash` directory.

To build the app, run :
```
go build fileHash.go
```

The usage is as shown below.
```
./hash <algorithm> <file name>
```

## Building the ecc sign/verify example

An application that tests ecc sign/verify on a sha512 hash with different key sizes. Located in `ecc-sign-verify` directory.

To build the app, run :
```
go build ecc-sign-verify.go
```

## Building the x509 cert verify example

An application that loads a root CA, two intermediate certs, then verifies the leaf cert. Make sure wolfSSL was configured with "--enable-opensslall" to run this example. Located in `x509` directory.

To build the app, run :
```
go build certVerify.go
```

## Building the x509 extract key example

An application that loads an X509 cert, extracts the public key DER buffer from it, and demonstrates how to import der buffer into an ecc key object. Make sure wolfSSL was configured with "--enable-opensslall" to run this example. Located in `x509` directory.

To build the app, run :
```
go build extractKey.go
```

