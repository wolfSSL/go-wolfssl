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

Then run the command below to build and install the wrapper module.
```
go get -u github.com/wolfssl/go-wolfssl 
```

## Building with configure options

If building wolfSSL with a non-empty configure, you'll have to run the `./generateOptions` executable to customize go-wolfssl to the same feature set as wolfSSL. This executable will generate an `options.go` file that will keep go-wolfssl and wolfSSL in sync. `generateOptions` should be run any time you change your wolfSSL configure options. 

Example: To use go-wolfssl without ECC, first build wolfSSL as shown below:
```
./configure --disable-ecc
make
sudo make install
``` 

Then go to the go-wolfssl directory and if the path to your wolfSSL directory is `../wolfssl`, just run:
```
./generateOptions
```

If you have a different path to your wolfSSL directory, create a file called `path.txt` with the right path and run the executable:
```
echo "../files/wolfssl/" > path.txt
./generateOptions
``` 

options.go is now generated and go-wolfssl can be run with ECC disabled!
 
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
