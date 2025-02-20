package sha256

import (
	"fmt"
	"hash"
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// Size is the size of a SHA256 checksum in bytes.
const Size = types.WC_SHA256_DIGEST_SIZE

// BlockSize is the block size of SHA256 in bytes.
const BlockSize = 64

type digest struct {
	ctx types.Sha256
}

// New returns a new hash.Hash computing the SHA256 checksum.
func New() hash.Hash {
	d := new(digest)
	if err := types.Wc_Sha256_Init(&d.ctx); err != 0 {
		panic("sha256: failed to initialize context")
	}
	return d
}

func (d *digest) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if ret := types.Wc_Sha256_Update(&d.ctx, p); ret != 0 {
		return 0, fmt.Errorf("sha256: update failed with code %d", ret)
	}
	return len(p), nil
}

func (d *digest) Sum(b []byte) []byte {
	// Make a copy of the context to avoid modifying the underlying state
	ctx := d.ctx
	h := make([]byte, Size)
	if err := types.Wc_Sha256_Final(&ctx, h); err != 0 {
		panic("sha256: failed to finalize hash")
	}
	return append(b, h...)
}

func (d *digest) Reset() {
	if err := types.Wc_Sha256_Init(&d.ctx); err != 0 {
		panic("sha256: failed to reset context")
	}
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

// Sum256 returns the SHA256 checksum of the data.
func Sum256(data []byte) [Size]byte {
	var h [Size]byte
	d := New()
	d.Write(data)
	sum := d.Sum(nil)
	copy(h[:], sum)
	return h
}
