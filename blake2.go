package wolfssl

import (
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// Blake2s represents a BLAKE2s hash.
type Blake2s struct {
	ctx [64]byte // Size of wolfCrypt Blake2s context
}

// Wc_InitBlake2s initializes a Blake2s hash context
func Wc_InitBlake2s(b *Blake2s) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

// Wc_Blake2sUpdate updates the Blake2s hash with data
func Wc_Blake2sUpdate(b *Blake2s, data []byte, sz int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

// Wc_Blake2sFinal finalizes the Blake2s hash
func Wc_Blake2sFinal(b *Blake2s, out []byte, sz int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

// Wc_Blake2s_HMAC computes HMAC using Blake2s
func Wc_Blake2s_HMAC(key []byte, keyLen int, in []byte, inLen int, out []byte, outLen int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

// New256 returns a new Blake2s-256 hash
func New256() *Blake2s {
	b := new(Blake2s)
	Wc_InitBlake2s(b)
	return b
}

// Write adds more data to the running hash
func (b *Blake2s) Write(p []byte) (n int, err error) {
	Wc_Blake2sUpdate(b, p, len(p))
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice
func (b *Blake2s) Sum(in []byte) []byte {
	out := make([]byte, types.WC_SHA256_DIGEST_SIZE)
	Wc_Blake2sFinal(b, out, types.WC_SHA256_DIGEST_SIZE)
	return append(in, out...)
}

// Reset resets the hash to its initial state
func (b *Blake2s) Reset() {
	Wc_InitBlake2s(b)
}

// Size returns the number of bytes Sum will return
func (b *Blake2s) Size() int {
	return types.WC_SHA256_DIGEST_SIZE
}

// BlockSize returns the hash's underlying block size
func (b *Blake2s) BlockSize() int {
	return 64
}

// Sum256 returns the Blake2s-256 checksum of the data
func Sum256(data []byte) [32]byte {
	b := New256()
	b.Write(data)
	sum := b.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out
}
