package types

import (
	"crypto/cipher"
	"hash"
	"io"
)

// Constants for key and signature sizes
const (
	WC_ECC_P256_SIGNATURE_SIZE = 64
	WC_ECC_P256_PUBLIC_KEY_SIZE = 65
	WC_ECC_P256_PRIVATE_KEY_SIZE = 32
	WC_SHA256_DIGEST_SIZE = 32
	WC_AES_GCM_AUTH_SZ = 16
	WC_AES_GCM_NONCE_SIZE = 12
	WC_UINT32_SIZE = 4
	WC_UINT64_SIZE = 8
	WC_MAX_MSG_SIZE = 4096
	WC_HEADER_SIZE = 3
)

// ECC curve types
const (
	ECC_SECP256R1 = 1
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
