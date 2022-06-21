# wolfSSL Golang Wrapper

This repository contains a very light wrapper around wolfSSL for GO and a server/client example. 

## Running the TLS Server/Client example

First build and install wolfSSL as shown below.

```
git clone https://github.com/wolfSSL/wolfssl
./autogen.sh
./configure
make
sudo make install
``` 

The example `.go` files are located in the `client` and `server` directories. 

Run the command below to build and install the go-wolfssl wrapper.
```
go get -u github.com/wolfssl/go-wolfssl 
```

To build the server, run :
```
cd server
go build server.go
```

To build the client, run :
```
cd client
go build client.go
```

Make sure to run both the server and client from within their directories or change the certificate and key paths in the code so that the files are found.

**NOTE**: If you have wolfSSL installed in a non-standard location, edit the `CFLAGS` and `LDFLAGS` specifications in `ssl.go` to correspond to your custom installation path.

## Support

For inquiries, suggestions and feedback please contact support@wolfssl.com.
