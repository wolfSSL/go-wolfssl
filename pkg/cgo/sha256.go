// Package cgo provides CGo bindings for wolfSSL
package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>

static int wc_Sha256Update_ex(Sha256* sha, const byte* data, word32 len) {
    if (!sha || !data) {
        return BAD_FUNC_ARG;
    }
    return wc_Sha256Update(sha, data, len);
}

static int wc_Sha256Final_ex(Sha256* sha, byte* hash) {
    if (!sha || !hash) {
        return BAD_FUNC_ARG;
    }
    return wc_Sha256Final(sha, hash);
}
*/
import "C"
import (
    "hash"
    "unsafe"
)

// Sha256 represents a SHA256 hash context
type Sha256 struct {
    ctx C.Sha256
}

// NewSha256 creates a new SHA256 hash context
func NewSha256() (hash.Hash, error) {
    h := &Sha256{}
    if ret := C.wc_InitSha256(&h.ctx); ret != 0 {
        return nil, WolfSSLError(ret)
    }
    return h, nil
}

// Write adds more data to the running hash
func (h *Sha256) Write(p []byte) (n int, err error) {
    if len(p) == 0 {
        return 0, nil
    }
    if ret := C.wc_Sha256Update_ex(&h.ctx, (*C.byte)(unsafe.Pointer(&p[0])), C.word32(len(p))); ret != 0 {
        return 0, WolfSSLError(ret)
    }
    return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice
func (h *Sha256) Sum(b []byte) []byte {
    hash := make([]byte, Size)
    if ret := C.wc_Sha256Final_ex(&h.ctx, (*C.byte)(unsafe.Pointer(&hash[0]))); ret != 0 {
        panic("wolfssl/sha256: " + WolfSSLError(ret).Error())
    }
    if b == nil {
        return hash
    }
    return append(b, hash...)
}

// Reset resets the hash to its initial state
func (h *Sha256) Reset() {
    if ret := C.wc_InitSha256(&h.ctx); ret != 0 {
        panic("wolfssl/sha256: " + WolfSSLError(ret).Error())
    }
}

// Size returns the number of bytes Sum will return
func (h *Sha256) Size() int {
    return Size
}

// BlockSize returns the hash's underlying block size
func (h *Sha256) BlockSize() int {
    return BlockSize
}
