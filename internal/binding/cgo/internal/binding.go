// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/error.h>
import "C"

// WolfSSLError represents a wolfSSL error code
type WolfSSLError int

func (e WolfSSLError) Error() string {
    return C.GoString(C.wc_GetErrorString(C.int(e)))
}
