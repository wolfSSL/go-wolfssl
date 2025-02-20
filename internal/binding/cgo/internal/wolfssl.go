// Package internal provides low-level C bindings to wolfSSL functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
import "C"

type WolfSSLError int

func (e WolfSSLError) Error() string {
    return C.GoString(C.wc_GetErrorString(C.int(e)))
}
