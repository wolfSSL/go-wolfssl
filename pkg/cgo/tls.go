// Package cgo provides CGo bindings for wolfSSL
package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
*/
import "C"
import "unsafe"

// TLS represents a TLS context
type TLS struct {
    ctx *C.WOLFSSL_CTX
}

// NewTLS creates a new TLS context
func NewTLS() (*TLS, error) {
    method := C.wolfTLSv1_3_client_method()
    if method == nil {
        return nil, WolfSSLError(-1)
    }

    ctx := C.wolfSSL_CTX_new(method)
    if ctx == nil {
        return nil, WolfSSLError(-1)
    }

    return &TLS{ctx: ctx}, nil
}

// Free frees the TLS context
func (t *TLS) Free() {
    C.wolfSSL_CTX_free(t.ctx)
}

// LoadCertificate loads a certificate from memory
func (t *TLS) LoadCertificate(cert []byte) error {
    ret := C.wolfSSL_CTX_use_certificate_buffer(t.ctx,
        (*C.uchar)(unsafe.Pointer(&cert[0])),
        C.long(len(cert)),
        C.SSL_FILETYPE_PEM)
    if ret != C.SSL_SUCCESS {
        return WolfSSLError(ret)
    }
    return nil
}

// LoadPrivateKey loads a private key from memory
func (t *TLS) LoadPrivateKey(key []byte) error {
    ret := C.wolfSSL_CTX_use_PrivateKey_buffer(t.ctx,
        (*C.uchar)(unsafe.Pointer(&key[0])),
        C.long(len(key)),
        C.SSL_FILETYPE_PEM)
    if ret != C.SSL_SUCCESS {
        return WolfSSLError(ret)
    }
    return nil
}

// LoadCA loads a CA certificate from memory
func (t *TLS) LoadCA(cert []byte) error {
    ret := C.wolfSSL_CTX_load_verify_buffer(t.ctx,
        (*C.uchar)(unsafe.Pointer(&cert[0])),
        C.long(len(cert)),
        C.SSL_FILETYPE_PEM)
    if ret != C.SSL_SUCCESS {
        return WolfSSLError(ret)
    }
    return nil
}
