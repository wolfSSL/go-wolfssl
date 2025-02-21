// Package hmac provides HMAC using wolfSSL
package hmac

import (
    "hash"
    "github.com/wolfssl/go-wolfssl/pkg/cgo"
)

// HMAC represents an HMAC hasher
type HMAC struct {
    hmac *cgo.Hmac
}

// New creates a new HMAC hasher using the given hash function
func New(h func() hash.Hash) hash.Hash {
    hmac, err := cgo.NewHmac()
    if err != nil {
        panic("wolfssl/hmac: " + err.Error())
    }
    return &HMAC{hmac: hmac}
}

// Write adds more data to the running hash
func (h *HMAC) Write(p []byte) (n int, err error) {
    if err := h.hmac.Write(p); err != nil {
        return 0, err
    }
    return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice
func (h *HMAC) Sum(b []byte) []byte {
    sum := h.hmac.Sum()
    if b == nil {
        return sum
    }
    return append(b, sum...)
}

// Reset resets the HMAC to its initial state
func (h *HMAC) Reset() {
    h.hmac.Reset()
}

// Size returns the number of bytes Sum will return
func (h *HMAC) Size() int {
    return h.hmac.Size()
}

// BlockSize returns the hash's underlying block size
func (h *HMAC) BlockSize() int {
    return h.hmac.BlockSize()
}
