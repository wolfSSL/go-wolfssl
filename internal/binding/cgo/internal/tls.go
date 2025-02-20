package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
import "C"
import (
    "errors"
    "unsafe"
)

// TLS constants
const (
    SSL_SUCCESS = int(C.SSL_SUCCESS)
    SSL_FAILURE = int(C.SSL_FAILURE)
)

// InitTLS initializes the wolfSSL library
func InitTLS() error {
    ret := C.wolfSSL_Init()
    if ret != SSL_SUCCESS {
        return WolfSSLError(ret)
    }
    return nil
}

// CreateTLSContext creates a new TLS context
func CreateTLSContext(method C.WOLFSSL_METHOD) (*C.WOLFSSL_CTX, error) {
    ctx := C.wolfSSL_CTX_new(method)
    if ctx == nil {
        return nil, errors.New("failed to create WOLFSSL_CTX")
    }
    return ctx, nil
}

// LoadCertificateChain loads a certificate chain into a TLS context
func LoadCertificateChain(ctx *C.WOLFSSL_CTX, cert []byte) error {
    ret := C.wolfSSL_CTX_use_certificate_chain_buffer(ctx,
        (*C.uchar)(unsafe.Pointer(&cert[0])),
        C.long(len(cert)))
    if ret != SSL_SUCCESS {
        return WolfSSLError(ret)
    }
    return nil
}

// LoadPrivateKey loads a private key into a TLS context
func LoadPrivateKey(ctx *C.WOLFSSL_CTX, key []byte) error {
    ret := C.wolfSSL_CTX_use_PrivateKey_buffer(ctx,
        (*C.uchar)(unsafe.Pointer(&key[0])),
        C.long(len(key)),
        C.SSL_FILETYPE_ASN1)
    if ret != SSL_SUCCESS {
        return WolfSSLError(ret)
    }
    return nil
}

// NewTLSConn creates a new TLS connection
func NewTLSConn(ctx *C.WOLFSSL_CTX) (*C.WOLFSSL, error) {
    ssl := C.wolfSSL_new(ctx)
    if ssl == nil {
        return nil, errors.New("failed to create WOLFSSL object")
    }
    return ssl, nil
}
