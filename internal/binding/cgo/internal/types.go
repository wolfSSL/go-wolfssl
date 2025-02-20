// Package internal provides low-level types for wolfSSL bindings
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/settings.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
import "C"

// Ecc_key represents a wolfSSL ECC key
type Ecc_key C.ecc_key

// WolfSSLError represents a wolfSSL error code
type WolfSSLError int32

// Error implements the error interface
func (e WolfSSLError) Error() string {
    return C.GoString(C.wc_GetErrorString(C.int(e)))
}

// Constants
const (
    WC_SHA256_DIGEST_SIZE = 32
    WC_SHA256_BLOCK_SIZE = 64
    WC_ECC_P256_SIGNATURE_SIZE = 64
    WC_ECC_P256_PUBLIC_KEY_SIZE = 65
    WC_ECC_P256_PRIVATE_KEY_SIZE = 32
    WC_AES_BLOCK_SIZE = 16
    WC_AES_128_KEY_SIZE = 16
    WC_AES_192_KEY_SIZE = 24
    WC_AES_256_KEY_SIZE = 32
    WC_AES_GCM_NONCE_SZ = 12
    WC_AES_GCM_AUTH_SZ = 16
    WC_HMAC_SHA256_SIZE = 32
    WC_POLY1305_MAC_SIZE = 16
)
