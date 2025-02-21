// Package sha256 provides SHA256 using wolfSSL
package sha256

import (
    "hash"
    "github.com/wolfssl/go-wolfssl/pkg/cgo"
)

// Size of SHA256 checksum in bytes
const Size = 32

// BlockSize of SHA256 in bytes
const BlockSize = 64

// New returns a new hash.Hash computing the SHA256 checksum
func New() hash.Hash {
    h, err := cgo.NewSha256()
    if err != nil {
        panic("wolfssl/sha256: " + err.Error())
    }
    return h
}

// Sum256 returns the SHA256 checksum of the data
func Sum256(data []byte) [Size]byte {
    h := New()
    h.Write(data)
    var sum [Size]byte
    h.Sum(sum[:0])
    return sum
}
