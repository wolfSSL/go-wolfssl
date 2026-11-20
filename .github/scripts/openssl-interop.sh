#!/bin/bash
# Usage: openssl-interop.sh <wolfssl-prefix>
# Runs the example TLS client against openssl s_server and the example TLS
# server against openssl s_client, and checks the exact messages each side
# receives. Run from the repository root.

set -euo pipefail

PORT=11111
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

# The examples load ../certs, so run them from a scratch tree whose certs are
# minted here: checked-in fixtures expire, a fresh CA does not.
mkdir -p "$WORK/client" "$WORK/server" "$WORK/certs"
CERTS=$WORK/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=interop CA" \
    -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca-cert.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=example.com" \
    -keyout "$CERTS/server-key.pem" -out "$CERTS/server.csr" 2>/dev/null
openssl x509 -req -in "$CERTS/server.csr" -CA "$CERTS/ca-cert.pem" -CAkey "$CERTS/ca-key.pem" \
    -CAcreateserial -days 2 -out "$CERTS/server-cert.pem" \
    -extfile <(printf 'subjectAltName=DNS:example.com,DNS:localhost,IP:127.0.0.1\n') 2>/dev/null

./generateOptions.sh "$1"
export LD_LIBRARY_PATH="$1/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
(cd examples/client && go build -o "$WORK/client/client" client.go)
(cd examples/server && go build -o "$WORK/server/server" server.go)

# Checks for a listening socket without connecting: a probe connection would
# use up a server that accepts only one client.
wait_for_port() {
    local _
    for _ in $(seq 50); do
        if [ -n "$(ss -Hltn "sport = :$PORT")" ]; then
            return 0
        fi
        sleep 0.2
    done
    echo "::error::nothing listening on port $PORT"
    return 1
}

expect() {
    if ! grep -qF "$2" "$1"; then
        echo "::error::$3"
        echo "--- $1"
        cat "$1"
        exit 1
    fi
}

# Fails unless the named process exited 0, showing its output.
require_ok() {
    if [ "$2" -ne 0 ]; then
        echo "::error::$1 exited with status $2"
        cat "$3"
        exit 1
    fi
}

echo "== example client -> openssl s_server"
(sleep 3; echo "I hear ya fashizzle!") | openssl s_server -accept "$PORT" -naccept 1 -quiet \
    -cert "$CERTS/server-cert.pem" -key "$CERTS/server-key.pem" > "$WORK/s_server.out" 2>&1 &
srv=$!
wait_for_port
st=0
(cd "$WORK/client" && timeout 20 ./client) > "$WORK/client.out" 2>&1 || st=$?
sst=0
wait "$srv" || sst=$?
expect "$WORK/client.out" "Server says :  I hear ya fashizzle!" "client did not receive the server reply"
expect "$WORK/s_server.out" "Can you hear me?" "openssl s_server did not receive the client message"
require_ok "example client" "$st" "$WORK/client.out"
require_ok "openssl s_server" "$sst" "$WORK/s_server.out"

echo "== openssl s_client -> example server"
(cd "$WORK/server" && timeout 20 ./server) > "$WORK/server.out" 2>&1 &
srv=$!
wait_for_port
st=0
(echo "Can you hear me?"; sleep 3) | timeout 20 openssl s_client -connect "127.0.0.1:$PORT" \
    -CAfile "$CERTS/ca-cert.pem" -verify_return_error -tls1_2 -quiet > "$WORK/s_client.out" 2>&1 || st=$?
sst=0
wait "$srv" || sst=$?
expect "$WORK/server.out" "Client says :  Can you hear me?" "server did not receive the client message"
expect "$WORK/s_client.out" "I hear ya fashizzle!" "openssl s_client did not receive the server reply"
require_ok "openssl s_client" "$st" "$WORK/s_client.out"
require_ok "example server" "$sst" "$WORK/server.out"

echo "OpenSSL interop passed"
