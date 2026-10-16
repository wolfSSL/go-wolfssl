#!/bin/bash
# Usage: analyze.sh <wolfssl-prefix>
# Runs go vet (every analyzer), staticcheck and govulncheck over the
# go-wolfssl packages and each example program, against the wolfSSL
# installed at <prefix>. staticcheck and govulncheck must be on PATH.

set -euo pipefail

PKGS=". ./handles ./sha256 ./wolftls ./wolfx509"

./generateOptions.sh "$1"
export LD_LIBRARY_PATH="$1/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# shellcheck disable=SC2086
go vet $PKGS
# Example directories hold several main programs, so vet each file alone,
# then vet directories with tests as packages so the tests are covered too.
grep -rl --include='*.go' --exclude='*_test.go' '^package main' examples | while read -r f; do
    echo "go vet $f"
    go vet "$f"
done
find examples -name '*_test.go' -exec dirname {} \; | sort -u | while read -r d; do
    echo "go vet ./$d"
    go vet "./$d"
done

# shellcheck disable=SC2086
staticcheck $PKGS
# Examples get the correctness checks; the ST* style checks are for the library.
grep -rl --include='*.go' --exclude='*_test.go' '^package main' examples | while read -r f; do
    echo "staticcheck $f"
    staticcheck -checks 'inherit,-ST*' "$f"
done

# shellcheck disable=SC2086
govulncheck $PKGS
# Examples cannot be loaded as packages, so scan each built program.
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
grep -rl --include='*.go' --exclude='*_test.go' '^package main' examples | while read -r f; do
    out="$bin/$(echo "$f" | tr '/.' '__')"
    go build -o "$out" "$f"
    echo "govulncheck -mode=binary $f"
    govulncheck -mode=binary "$out"
done
