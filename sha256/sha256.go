package sha256

import (
	"fmt"
	"hash"
	wolfSSL "github.com/wolfssl/go-wolfssl"
)

type sha256Hash struct {
	sha wolfSSL.Wc_Sha256
}

func New() hash.Hash {
	var sha wolfSSL.Wc_Sha256
	if ret := wolfSSL.Wc_InitSha256_ex(&sha, nil, 0); ret != 0 {
		panic("failed to initialize SHA-256")
	}
	return &sha256Hash{sha: sha}
}

func (h *sha256Hash) Write(p []byte) (n int, err error) {
	if ret := wolfSSL.Wc_Sha256Update(&h.sha, p, len(p)); ret != 0 {
		return 0, fmt.Errorf("failed to update SHA-256")
	}
	return len(p), nil
}

func (h *sha256Hash) Sum(b []byte) []byte {
	var out [32]byte
	if ret := wolfSSL.Wc_Sha256Final(&h.sha, out[:]); ret != 0 {
		panic("failed to finalize SHA-256")
	}
	return append(b, out[:]...)
}

func (h *sha256Hash) Reset() {
	if ret := wolfSSL.Wc_InitSha256_ex(&h.sha, nil, 0); ret != 0 {
		panic("failed to initialize SHA-256")
	}
}

func (h *sha256Hash) Size() int      { return 32 }
func (h *sha256Hash) BlockSize() int { return 64 }

func Sum256(data []byte) [32]byte {
	var sha wolfSSL.Wc_Sha256
	var out [32]byte
	if ret := wolfSSL.Wc_InitSha256_ex(&sha, nil, 0); ret != 0 {
		panic("failed to initialize SHA-256")
	}
	if ret := wolfSSL.Wc_Sha256Update(&sha, data, len(data)); ret != 0 {
		panic("failed to update SHA-256")
	}
	if ret := wolfSSL.Wc_Sha256Final(&sha, out[:]); ret != 0 {
		panic("failed to finalize SHA-256")
	}
	wolfSSL.Wc_Sha256Free(&sha)
	return out
}
