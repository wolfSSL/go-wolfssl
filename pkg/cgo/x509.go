// Package cgo provides CGo bindings for wolfSSL
package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

// X509 functions
// X509 functions
static WOLFSSL_X509* wolfSSL_d2i_X509_ex(const unsigned char* input, long length) {
    if (!input || length <= 0) {
        return NULL;
    }
    const unsigned char* ptr = input;
    return wolfSSL_d2i_X509(NULL, &ptr, length);
}

static void wolfSSL_X509_free_ex(WOLFSSL_X509* x509) {
    if (x509) {
        wolfSSL_X509_free(x509);
    }
}

// X509 Store functions
static WOLFSSL_X509_STORE* wolfSSL_X509_STORE_new_ex(void) {
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    if (!store) {
        return NULL;
    }
    return store;
}

static void wolfSSL_X509_STORE_free_ex(WOLFSSL_X509_STORE* store) {
    if (store) {
        wolfSSL_X509_STORE_free(store);
    }
}

static int wolfSSL_X509_STORE_add_cert_ex(WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509) {
    if (!store || !x509) {
        return SSL_FAILURE;
    }
    return wolfSSL_X509_STORE_add_cert(store, x509);
}

// X509 Store Context functions
static WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new_ex(void) {
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    if (!ctx) {
        return NULL;
    }
    return ctx;
}

static void wolfSSL_X509_STORE_CTX_free_ex(WOLFSSL_X509_STORE_CTX* ctx) {
    if (ctx) {
        wolfSSL_X509_STORE_CTX_free(ctx);
    }
}

static int wolfSSL_X509_STORE_CTX_init_ex(WOLFSSL_X509_STORE_CTX* ctx, WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509) {
    if (!ctx || !store || !x509) {
        return SSL_FAILURE;
    }
    return wolfSSL_X509_STORE_CTX_init(ctx, store, x509, NULL);
}

static int wolfSSL_X509_verify_cert_ex(WOLFSSL_X509_STORE_CTX* ctx) {
    if (!ctx) {
        return SSL_FAILURE;
    }
    return wolfSSL_X509_verify_cert(ctx);
}
*/
import "C"
import (
    "runtime"
    "unsafe"
)

// X509Certificate represents an X.509 certificate
type X509Certificate struct {
    cert *C.WOLFSSL_X509
    raw  []byte
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data
func ParseCertificate(asn1Data []byte) (*X509Certificate, error) {
    if len(asn1Data) == 0 {
        return nil, WolfSSLError(-1)
    }

    cert := &X509Certificate{
        raw: make([]byte, len(asn1Data)),
    }
    copy(cert.raw, asn1Data)

    ptr := (*C.uchar)(unsafe.Pointer(&cert.raw[0]))
    cert.cert = C.wolfSSL_d2i_X509_ex(ptr, C.long(len(cert.raw)))
    if cert.cert == nil {
        return nil, WolfSSLError(-1)
    }

    runtime.SetFinalizer(cert, func(c *X509Certificate) {
        c.Free()
    })

    return cert, nil
}

// Free frees the X.509 certificate
func (c *X509Certificate) Free() {
    if c.cert != nil {
        C.wolfSSL_X509_free_ex(c.cert)
        c.cert = nil
    }
}

// Verify verifies the certificate against the given root certificates
func (c *X509Certificate) Verify(roots []*X509Certificate) error {
    if c.cert == nil {
        return WolfSSLError(-1)
    }

    // Create a new certificate store
    store := C.wolfSSL_X509_STORE_new_ex()
    if store == nil {
        return WolfSSLError(-1)
    }
    defer C.wolfSSL_X509_STORE_free_ex(store)

    // Add root certificates
    for _, root := range roots {
        if root.cert == nil {
            return WolfSSLError(-1)
        }
        if C.wolfSSL_X509_STORE_add_cert_ex(store, root.cert) != C.SSL_SUCCESS {
            return WolfSSLError(-1)
        }
    }

    // Create verification context
    ctx := C.wolfSSL_X509_STORE_CTX_new_ex()
    if ctx == nil {
        return WolfSSLError(-1)
    }
    defer C.wolfSSL_X509_STORE_CTX_free_ex(ctx)

    // Initialize verification context
    if C.wolfSSL_X509_STORE_CTX_init_ex(ctx, store, c.cert) != C.SSL_SUCCESS {
        return WolfSSLError(-1)
    }

    // Verify certificate
    if C.wolfSSL_X509_verify_cert_ex(ctx) != C.SSL_SUCCESS {
        return WolfSSLError(-1)
    }

    return nil
}
