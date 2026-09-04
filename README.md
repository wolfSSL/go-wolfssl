# wolfSSL Golang Wrapper

This repository contains a very light wrapper around wolfSSL for GO, a
server/client example, and some example wolfCrypt applications.

## Usage

To use the wolfSSL go module, first build and install wolfSSL as shown below.

```bash
git clone https://github.com/wolfSSL/wolfssl
cd wolfssl
./autogen.sh
./configure
make
sudo make install
```

If you plan to use the `wolftls` subpackage and need concurrent `Read` and
`Write` on a single `Conn` to run in parallel, add `--enable-writedup` to the
`./configure` line above. Otherwise, the calls will be serialized.

Once wolfSSL is installed clone the go-wolfssl repo into the same parent
directory.

```bash
git clone https://github.com/wolfSSL/go-wolfssl
```

The directory structure should be similar to the following:

```
parent-dir/
|-- wolfssl/
`-- go-wolfssl/
```

Inside the go-wolfssl directory run the `./generateOptions.sh` script to
customize go-wolfssl to the same feature set as wolfSSL. This script will
generate an `options.go` file that will keep go-wolfssl and wolfSSL in sync.
Ideally, `generateOptions` should be run any time the wolfSSL install is
modified. At minimum, it should be run whenever the configure changes. If the
path to wolfssl/ from inside go-wolfssl/ is `../wolfssl`, just run:

```bash
cd go-wolfssl
./generateOptions.sh
```

If you have a different path to your wolfSSL directory, run the script with
the right path:

```bash
./generateOptions.sh /path/to/wolfssl
```

If wolfSSL is installed (i.e. `make install`'d to a custom `--prefix=...` path),
pass the install prefix instead:

```bash
./generateOptions.sh /usr/local        # system install
./generateOptions.sh /opt/wolfssl-fips # custom prefix
```

Every invocation regenerates `options.go` and rewrites the `#cgo`
`CFLAGS` / `LDFLAGS` directives in every cgo-bearing file, so the whole tree
agrees on one wolfSSL. An install prefix points the files at the given prefix.
A source root or no argument will point the files at `/usr/local`.

The prefix may contain only letters, digits and `/ _ . : + -`, since a `#cgo`
directive cannot express a path containing spaces or shell metacharacters.
Anything else is rejected. On any failure the script exits 99 and leaves the
tree as it found it.

To install the wrapper module, run these commands:

```bash
go get -u github.com/wolfssl/go-wolfssl
go mod edit -replace github.com/wolfssl/go-wolfssl=</path/to/go-wolfssl>
```

## Running the TLS Server/Client example

The example `.go` files are located in the `client` and `server` directories.

To build the server, run:

```bash
cd examples/server
go build server.go
```

To build the client, run:

```bash
cd examples/client
go build client.go
```

**NOTE**: Make sure to run both the server and client from within their
directories or change the certificate and key paths in the code so that the
files are found.

See [examples/README.md](examples/README.md) for details on building/running
the other examples.

## Support

For inquiries, suggestions and feedback please contact support@wolfssl.com.
