# wolfSSL Golang Wrapper

This repository contains a very light wrapper around wolfSSL for GO, a server/client example, and some example wolfCrypt applications. 

## Usage

To use the wolfSSL go module, first build and install wolfSSL as shown below.

```
git clone https://github.com/wolfSSL/wolfssl
./autogen.sh
./configure
make
sudo make install
``` 

Then clone the go-wolfssl repo and run the `./generateOptions.sh` script to customize go-wolfssl to the same feature set as wolfSSL. This script will generate an `options.go` file that will keep go-wolfssl and wolfSSL in sync. `generateOptions` should be run any time you change your wolfSSL configure options. If the path to your wolfSSL directory is `../wolfssl`, just run: 
```
git clone https://github.com/wolfSSL/go-wolfssl
cd go-wolfssl
./generateOptions.sh
``` 

If you have a different path to your wolfSSL directory, run the script with the right path:
```
./generateOptions ../files/wolfSSL
``` 

To install the wrapper module, run these commands:
```
go get -u github.com/wolfssl/go-wolfssl 
go mod edit -replace github.com/wolfssl/go-wolfssl=<path to your go-wolfssl directory>
```

## Running the TLS Server/Client example

The example `.go` files are located in the `client` and `server` directories. 

To build the server, run :
```
cd examples/server
go build server.go
```

To build the client, run :
```
cd examples/client
go build client.go
```

**NOTE**: Make sure to run both the server and client from within their directories or change the certificate and key paths in the code so that the files are found.

See [examples/README.md](examples/README.md) for details on building/running the other examples.

**NOTE**: If you have wolfSSL installed in a non-standard location, edit the `CFLAGS` and `LDFLAGS` specifications in the `*.go` source files to correspond to your custom installation path.

## Support

For inquiries, suggestions and feedback please contact support@wolfssl.com.
