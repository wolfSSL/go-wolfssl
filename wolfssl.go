package wolfssl

import (
	"crypto/cipher"
	"hash"
	"io"

	"github.com/wolfssl/go-wolfssl/aes"
	"github.com/wolfssl/go-wolfssl/ecc"
	"github.com/wolfssl/go-wolfssl/internal/types"
	"github.com/wolfssl/go-wolfssl/kdf"
	"github.com/wolfssl/go-wolfssl/random"
	"github.com/wolfssl/go-wolfssl/sha256"
)

// Re-export constants from internal/types
const (
	WC_ECC_P256_SIGNATURE_SIZE  = types.WC_ECC_P256_SIGNATURE_SIZE
	WC_ECC_P256_PUBLIC_KEY_SIZE = types.WC_ECC_P256_PUBLIC_KEY_SIZE
	WC_ECC_P256_PRIVATE_KEY_SIZE = types.WC_ECC_P256_PRIVATE_KEY_SIZE
	WC_SHA256_DIGEST_SIZE       = types.WC_SHA256_DIGEST_SIZE
	WC_AES_GCM_AUTH_SZ         = types.WC_AES_GCM_AUTH_SZ
	WC_AES_GCM_NONCE_SIZE      = types.WC_AES_GCM_NONCE_SIZE
	WC_UINT32_SIZE             = types.WC_UINT32_SIZE
	WC_UINT64_SIZE             = types.WC_UINT64_SIZE
	WC_MAX_MSG_SIZE            = types.WC_MAX_MSG_SIZE
	WC_HEADER_SIZE             = types.WC_HEADER_SIZE
	ECC_SECP256R1             = types.ECC_SECP256R1
)

// Random provides FIPS-compliant random number generation
var Random = struct {
	Reader io.Reader
}{
	Reader: random.Reader,
}

// ECC provides FIPS-compliant elliptic curve cryptography
var ECC = struct {
	GenerateKey              func(curve int) (*ecc.Key, error)
	Sign                     func(priv *ecc.Key, message []byte) ([]byte, error)
	Verify                   func(pub []byte, message []byte, sig []byte) bool
	ImportPrivate            func(curve int, data []byte) (*ecc.Key, error)
	ImportPublic             func(curve int, data []byte) ([]byte, error)
	ImportPublicFromPrivate  func(priv *ecc.Key) ([]byte, error)
	ExportPublicFromPrivate  func(priv *ecc.Key) ([]byte, error)
}{
	GenerateKey:             ecc.GenerateKey,
	Sign:                    ecc.Sign,
	Verify:                  ecc.Verify,
	ImportPrivate:           ecc.ImportPrivate,
	ImportPublic:            ecc.ImportPublic,
	ImportPublicFromPrivate: ecc.ImportPublicFromPrivate,
	ExportPublicFromPrivate: ecc.ExportPublicFromPrivate,
}

// SHA256 provides FIPS-compliant SHA256 hashing
var SHA256 = struct {
	New  func() hash.Hash
	Sum  func(data []byte) [32]byte
}{
	New:  sha256.New,
	Sum:  sha256.Sum256,
}

// HKDF performs HMAC-based Key Derivation Function
func HKDF(hashType int, secret, salt, info []byte, out []byte) error {
	result, err := kdf.HKDF(secret, salt, info, len(out))
	if err != nil {
		return err
	}
	copy(out, result)
	return nil
}

// AES provides FIPS-compliant AES encryption
var AES = struct {
	Seal func(key []byte, nonce []byte, plaintext []byte) ([]byte, error)
	Open func(key []byte, nonce []byte, ciphertext []byte) ([]byte, error)
}{
	Seal: aes.Seal,
	Open: aes.Open,
}
