package sha256

import (
	"hash"
	wolfSSL "github.com/wolfssl/go-wolfssl"
	"github.com/wolfssl/go-wolfssl/internal/binding"
)

// Size of a SHA256 checksum in bytes.
const Size = 32

// BlockSize of SHA256 in bytes.
const BlockSize = 64

type digest struct {
	hash wolfSSL.WC_SHA256
}

// New returns a new hash.Hash computing the SHA256 checksum.
func New() hash.Hash {
	d := new(digest)
	binding.Wc_Sha256_Init(&d.hash)
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	binding.Wc_Sha256_Init(&d.hash)
}

// Write adds more data to the running hash.
func (d *digest) Write(p []byte) (n int, err error) {
	if ret := binding.Wc_Sha256_Update(&d.hash, p, len(p)); ret != 0 {
		return 0, nil
	}
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
func (d *digest) Sum(b []byte) []byte {
	var hash [Size]byte
	d2 := *d
	binding.Wc_Sha256_Final(&d2.hash, hash[:])
	return append(b, hash[:]...)
}

// Size returns the number of bytes Sum will return.
func (d *digest) Size() int { return Size }

// BlockSize returns the hash's underlying block size.
func (d *digest) BlockSize() int { return BlockSize }

// Sum256 returns the SHA256 checksum of the data.
func Sum256(data []byte) [Size]byte {
	var d digest
	binding.Wc_Sha256_Init(&d.hash)
	wolfSSL.Wc_Sha256_Update(&d.hash, data, len(data))
	var out [Size]byte
	wolfSSL.Wc_Sha256_Final(&d.hash, out[:])
	return out
}
