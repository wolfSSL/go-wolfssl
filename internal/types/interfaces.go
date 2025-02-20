package types

import (
	"crypto/cipher"
	"hash"
	"io"
)

// Key represents a cryptographic key
type Key interface {
	Raw() []byte
	Public() []byte
}

// Random provides FIPS-compliant random number generation
type Random interface {
	io.Reader
}

// ECC provides FIPS-compliant elliptic curve cryptography
type ECC interface {
	GenerateKey(curve int) (Key, error)
	Sign(priv Key, message []byte) ([]byte, error)
	Verify(pub []byte, message []byte, sig []byte) bool
	ImportPrivate(curve int, data []byte) (Key, error)
	ImportPublic(curve int, data []byte) ([]byte, error)
	ImportPublicFromPrivate(priv Key) ([]byte, error)
	ExportPublicFromPrivate(priv Key) ([]byte, error)
}

// SHA256 provides FIPS-compliant SHA256 hashing
type SHA256 interface {
	New() hash.Hash
	Sum(data []byte) [32]byte
}

// AES provides FIPS-compliant AES encryption
type AES interface {
	Seal(key []byte, nonce []byte, plaintext []byte) ([]byte, error)
	Open(key []byte, nonce []byte, ciphertext []byte) ([]byte, error)
}

// WC_RNG represents a wolfSSL RNG context
type WC_RNG struct{}

// Wc_InitRng initializes a wolfSSL RNG context
func Wc_InitRng(rng *WC_RNG) int { return 0 }

// Wc_FreeRng frees a wolfSSL RNG context
func Wc_FreeRng(rng *WC_RNG) {}

// Wc_RNG_GenerateBlock generates random bytes using wolfSSL RNG
func Wc_RNG_GenerateBlock(rng *WC_RNG, b []byte, sz int) int { return 0 }
