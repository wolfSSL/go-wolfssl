// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/sha256.h>
import "C"
import "unsafe"

// NewSHA256 creates a new SHA256 hash instance
func NewSHA256() (*C.wc_Sha256, error) {
    var sha C.wc_Sha256
    ret := C.wc_InitSha256(&sha)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    return &sha, nil
}

// SHA256Sum computes the SHA256 hash of data
func SHA256Sum(data []byte) ([]byte, error) {
    var sha C.wc_Sha256
    ret := C.wc_InitSha256(&sha)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_Sha256Free(&sha)

    ret = C.wc_Sha256Update(&sha, (*C.byte)(unsafe.Pointer(&data[0])), C.word32(len(data)))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    hash := make([]byte, WC_SHA256_DIGEST_SIZE)
    ret = C.wc_Sha256Final(&sha, (*C.byte)(unsafe.Pointer(&hash[0])))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    return hash, nil
}
