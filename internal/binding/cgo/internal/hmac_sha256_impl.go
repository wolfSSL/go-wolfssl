// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/hmac.h>
import "C"
import "unsafe"

// HmacSha256 computes HMAC using SHA256
func HmacSha256(key, data []byte) ([]byte, error) {
    var hmac C.Hmac
    ret := C.wc_HmacInit(&hmac, nil, -1)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_HmacFree(&hmac)

    ret = C.wc_HmacSetKey(&hmac, C.WC_SHA256, (*C.byte)(unsafe.Pointer(&key[0])), C.word32(len(key)))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    ret = C.wc_HmacUpdate(&hmac, (*C.byte)(unsafe.Pointer(&data[0])), C.word32(len(data)))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    digest := make([]byte, WC_HMAC_SHA256_SIZE)
    ret = C.wc_HmacFinal(&hmac, (*C.byte)(unsafe.Pointer(&digest[0])))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    return digest, nil
}

// NewHMAC creates a new HMAC instance
func NewHMAC(key []byte) (*C.Hmac, error) {
    var hmac C.Hmac
    ret := C.wc_HmacInit(&hmac, nil, -1)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    ret = C.wc_HmacSetKey(&hmac, C.WC_SHA256, (*C.byte)(unsafe.Pointer(&key[0])), C.word32(len(key)))
    if ret != 0 {
        C.wc_HmacFree(&hmac)
        return nil, WolfSSLError(ret)
    }

    return &hmac, nil
}
