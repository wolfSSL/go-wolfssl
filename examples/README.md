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
go build file-hash.go
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

