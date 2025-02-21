// Package cgo provides CGo bindings for wolfSSL
package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
*/
import "C"

// WolfSSLError represents a wolfSSL error code
type WolfSSLError C.int

// Error implements the error interface
func (e WolfSSLError) Error() string {
    return C.GoString(C.wc_GetErrorString(C.int(e)))
}
