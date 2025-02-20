package sha256

import (
	"hash"
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// Size is the size of a SHA256 checksum in bytes.
const Size = types.WC_SHA256_DIGEST_SIZE

// BlockSize is the block size of SHA256 in bytes.
const BlockSize = 64

type digest struct {
	h [Size]byte
}

// New returns a new hash.Hash computing the SHA256 checksum.
func New() hash.Hash {
	d := new(digest)
	// TODO: Initialize wolfSSL SHA256 context
	return d
}

func (d *digest) Write(p []byte) (n int, err error) {
	// TODO: Update wolfSSL SHA256 context
	return len(p), nil
}

func (d *digest) Sum(b []byte) []byte {
	// TODO: Finalize wolfSSL SHA256 context
	return append(b, d.h[:]...)
}

func (d *digest) Reset() {
	// TODO: Reset wolfSSL SHA256 context
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

// Sum256 returns the SHA256 checksum of the data.
func Sum256(data []byte) [Size]byte {
	var h [Size]byte
	// TODO: Compute SHA256 hash using wolfSSL
	return h
}
