#!/bin/bash
# Usage:
#   run-config.sh flags <config>            print the wolfSSL ./configure flags
#   run-config.sh test  <config> <prefix>   build and test go-wolfssl against
#                                            the wolfSSL installed at <prefix>
#
# Each config states which wolfSSL defines it must (or must not) have, which
# packages are tested, which are only built and linked, and which must fail
# to build with a given message because the build lacks a required feature.

set -euo pipefail

ALL="--enable-all --enable-opensslall --enable-opensslextra"
PKGS_ALL=". ./handles ./sha256 ./wolftls ./wolfx509"
X509_MISSING="wolfx509 requires wolfSSL built with"
# Tests on master that assume OPENSSL_EXTRA, ALPN or peer-cert support instead
# of skipping without it. Drop names from this list as they learn to skip.
FEATURE_TESTS="^(TestVerifyConnectionCallback|TestPeerCertificatesPopulated"
FEATURE_TESTS="$FEATURE_TESTS|TestVerifyPeerCertificateCallback|TestMinMaxVersion"
FEATURE_TESTS="$FEATURE_TESTS|TestGetCertificate|TestPeerCertsSurviveClose"
FEATURE_TESTS="$FEATURE_TESTS|TestALPN|TestUnknownClientAuthFailsClosed)$"

config() {
    FLAGS="" HAVE="" LACK="" TEST="" BUILD="" FAIL="" FAIL_MSG="" RACE=0 SKIP=""
    STRICT=0 TLS10=0
    EXAMPLES=1
    case "$1" in
    all)
        STRICT=1
        FLAGS="$ALL"
        HAVE="OPENSSL_ALL SESSION_CERTS KEEP_PEER_CERT HAVE_SNI WOLFSSL_CERT_SETUP_CB"
        TEST="$PKGS_ALL" RACE=1 ;;
    default)
        LACK="OPENSSL_EXTRA SESSION_CERTS WOLFSSL_CERT_GEN"
        TEST=". ./handles ./sha256 ./wolftls" SKIP="$FEATURE_TESTS"
        FAIL="./wolfx509" FAIL_MSG="$X509_MISSING" ;;
    opensslextra)
        FLAGS="--enable-opensslextra"
        HAVE="OPENSSL_EXTRA" LACK="OPENSSL_ALL WOLFSSL_CERT_GEN"
        TEST=". ./handles ./sha256 ./wolftls" SKIP="$FEATURE_TESTS"
        FAIL="./wolfx509" FAIL_MSG="$X509_MISSING" ;;
    writedup)
        STRICT=1
        FLAGS="$ALL --enable-writedup"
        HAVE="HAVE_WRITE_DUP"
        TEST="./wolftls ./handles" RACE=1 EXAMPLES=0 ;;
    oldtls)
        STRICT=1
        FLAGS="$ALL --enable-oldtls --enable-tlsv10"
        HAVE="WOLFSSL_ALLOW_TLSV10" LACK="NO_OLD_TLS" TLS10=1
        TEST="./wolftls" EXAMPLES=0 ;;
    notls13)
        # --enable-all pulls in QUIC and DTLS 1.3, which need TLS 1.3.
        FLAGS="--enable-opensslall --enable-opensslextra --enable-certgen"
        FLAGS="$FLAGS --enable-certext --enable-certreq --enable-keygen --enable-sni"
        FLAGS="$FLAGS --enable-alpn --enable-sessioncerts --disable-tls13"
        FLAGS="$FLAGS CPPFLAGS='-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_SETUP_CB'"
        HAVE="OPENSSL_ALL WOLFSSL_CERT_GEN" LACK="WOLFSSL_TLS13"
        TEST="$PKGS_ALL" SKIP='^TestMinMaxVersion$/^TLS_1\.3_only$' ;;
    reduced1)
        FLAGS="--disable-sni --disable-aes --disable-aesgcm --disable-aescbc"
        FLAGS="$FLAGS --enable-certgen --enable-certext CPPFLAGS=-DWOLFSSL_ALT_NAMES"
        HAVE="NO_AES WOLFSSL_ALT_NAMES" LACK="HAVE_SNI"
        BUILD=". ./wolftls ./wolfx509" EXAMPLES=0 ;;
    reduced2)
        FLAGS="--disable-sha256 --disable-rsa --enable-pwdbased"
        FLAGS="$FLAGS --disable-pkcs8 --disable-pkcs12 CPPFLAGS=-DWOLFSSL_NO_PEM"
        # wolfSSL's own unit tests, and 5.9.4's random.c under -Werror, break without SHA-256.
        FLAGS="$FLAGS --disable-examples ac_cv_vcs_checkout=no"
        HAVE="NO_SHA256 NO_RSA NO_PKCS8 WOLFSSL_NO_PEM"
        BUILD=". ./wolftls ./handles" EXAMPLES=0 ;;
    certgen-noext)
        FLAGS="--enable-certgen"
        HAVE="WOLFSSL_CERT_GEN" LACK="WOLFSSL_CERT_EXT"
        BUILD=". ./handles"
        FAIL="./wolfx509" FAIL_MSG="$X509_MISSING" EXAMPLES=0 ;;
    fips-ready)
        STRICT=1
        FLAGS="--enable-fips=ready --enable-opensslextra --enable-certgen"
        FLAGS="$FLAGS --enable-certext --enable-certreq --enable-keygen --enable-sni"
        FLAGS="$FLAGS --enable-alpn --enable-sessioncerts"
        FLAGS="$FLAGS CPPFLAGS='-DWOLFSSL_ALT_NAMES -DWOLFSSL_CERT_SETUP_CB'"
        HAVE="HAVE_FIPS OPENSSL_EXTRA WOLFSSL_CERT_GEN HAVE_ALPN SESSION_CERTS"
        TEST="$PKGS_ALL" ;;
    *)
        echo "unknown config: $1" >&2
        exit 2 ;;
    esac
}

has_define() {
    grep -q "^#define $1\b" "$2"
}

check_defines() {
    local opts=$1/include/wolfssl/options.h d
    for d in $HAVE; do
        has_define "$d" "$opts" || { echo "::error::expected $d in $opts"; exit 1; }
    done
    for d in $LACK; do
        if has_define "$d" "$opts"; then
            echo "::error::did not expect $d in $opts"
            exit 1
        fi
    done
}

# Builds each example program by file, since several share a directory,
# then runs the tests of example directories that have them.
build_examples() {
    local f d
    grep -rl --include='*.go' --exclude='*_test.go' '^package main' examples | while read -r f; do
        echo "go build $f"
        # shellcheck disable=SC2086
        go build $1 -o /dev/null "$f"
    done
    find examples -name '*_test.go' -exec dirname {} \; | sort -u | while read -r d; do
        # shellcheck disable=SC2086
        go test -count=1 $1 "./$d"
    done
}

run_tests() {
    local prefix=$2 tflags pkg out
    config "$1"
    check_defines "$prefix"

    if [ "$STRICT" = 1 ]; then
        export WOLFTLS_INTEROP_STRICT=1
    fi
    if [ "$TLS10" = 1 ]; then
        export WOLFTLS_INTEROP_TLS10=1
    fi
    ./generateOptions.sh "$prefix"
    export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    go clean -cache

    # -race also turns on checkptr; other configs ask for checkptr directly.
    # GO_TEST_FLAGS replaces both, for example with -asan.
    if [ -n "${GO_TEST_FLAGS:-}" ]; then
        tflags=$GO_TEST_FLAGS
    elif [ "$RACE" = 1 ]; then
        tflags="-race"
    else
        tflags="-gcflags=all=-d=checkptr"
    fi

    if [ -n "$TEST$BUILD" ]; then
        # shellcheck disable=SC2086
        go vet $TEST $BUILD
    fi
    if [ -n "$TEST" ]; then
        # shellcheck disable=SC2086
        go test -count=1 -timeout 15m $tflags ${SKIP:+-skip "$SKIP"} $TEST
    fi
    if [ -n "$BUILD" ]; then
        # shellcheck disable=SC2086
        go test -count=1 -run '^$' $BUILD
    fi
    for pkg in $FAIL; do
        if out=$(go build "$pkg" 2>&1); then
            echo "::error::$pkg built, but this config lacks a feature it requires"
            exit 1
        fi
        if ! grep -qF "$FAIL_MSG" <<<"$out"; then
            echo "$out"
            echo "::error::$pkg failed to build for an unexpected reason"
            exit 1
        fi
        echo "$pkg refused the build as expected: $FAIL_MSG"
    done
    if [ "$EXAMPLES" = 1 ]; then
        build_examples "$tflags"
    fi
}

case "${1:-}" in
flags)
    config "$2"
    echo "$FLAGS" ;;
test)
    run_tests "$2" "$3" ;;
*)
    echo "usage: $0 flags <config> | test <config> <prefix>" >&2
    exit 2 ;;
esac
