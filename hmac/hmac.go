package hmac

import (
    "hash"
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
)

type hmac struct {
    key  []byte
    hash hash.Hash
    size int
}

// New creates a new HMAC using the given hash function
func New(h func() hash.Hash, key []byte) hash.Hash {
    hm := &hmac{
        key:  make([]byte, len(key)),
        hash: h(),
        size: h().Size(),
    }
    copy(hm.key, key)
    return hm
}

func (h *hmac) Write(p []byte) (n int, err error) {
    h.hash.Write(p)
    return len(p), nil
}

func (h *hmac) Sum(b []byte) []byte {
    mac, err := cgo.HmacSha256(h.key, h.hash.Sum(nil))
    if err != nil {
        panic("hmac: " + err.Error())
    }
    if b == nil {
        return mac
    }
    return append(b, mac...)
}

func (h *hmac) Reset() {
    h.hash.Reset()
}

func (h *hmac) Size() int {
    return h.size
}

func (h *hmac) BlockSize() int {
    return h.hash.BlockSize()
}
