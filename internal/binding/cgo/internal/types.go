// Package internal provides low-level types for wolfSSL bindings
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/settings.h>
// #include <wolfssl/wolfcrypt/ecc.h>
import "C"

// Ecc_key represents a wolfSSL ECC key
type Ecc_key struct {
    key C.ecc_key
}

// WolfSSLError represents a wolfSSL error code
type WolfSSLError int32

// Error implements the error interface
func (e WolfSSLError) Error() string {
    return C.GoString(C.wc_GetErrorString(C.int(e)))
}
