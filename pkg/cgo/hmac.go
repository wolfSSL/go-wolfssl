// Package cgo provides CGo bindings for wolfSSL
package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>
*/
import "C"
import "unsafe"

// Hmac represents an HMAC hasher
type Hmac struct {
    hmac C.Hmac
}

// NewHmac creates a new HMAC hasher
func NewHmac() (*Hmac, error) {
    hmac := &Hmac{}
    ret := C.wc_HmacInit(&hmac.hmac, nil, -1)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    return hmac, nil
}

// Write adds more data to the running hash
func (h *Hmac) Write(data []byte) error {
    ret := C.wc_HmacUpdate(&h.hmac, (*C.byte)(unsafe.Pointer(&data[0])), C.word32(len(data)))
    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}

// Sum returns the current hash
func (h *Hmac) Sum() []byte {
    out := make([]byte, h.Size())
    ret := C.wc_HmacFinal(&h.hmac, (*C.byte)(unsafe.Pointer(&out[0])))
    if ret != 0 {
        panic("wolfssl/hmac: " + WolfSSLError(ret).Error())
    }
    return out
}

// Reset resets the HMAC to its initial state
func (h *Hmac) Reset() {
    C.wc_HmacFree(&h.hmac)
    C.wc_HmacInit(&h.hmac, nil, -1)
}

// Size returns the number of bytes Sum will return
func (h *Hmac) Size() int {
    return int(C.WC_SHA256_DIGEST_SIZE)
}

// BlockSize returns the hash's underlying block size
func (h *Hmac) BlockSize() int {
    return int(C.WC_SHA256_BLOCK_SIZE)
}
