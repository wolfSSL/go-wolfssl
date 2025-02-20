package binding

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
    "github.com/wolfssl/go-wolfssl/internal/types"
)

// Re-export constants
const (
    WC_ECC_P256_SIGNATURE_SIZE = types.WC_ECC_P256_SIGNATURE_SIZE
    WC_ECC_P256_PUBLIC_KEY_SIZE = types.WC_ECC_P256_PUBLIC_KEY_SIZE
    WC_ECC_P256_PRIVATE_KEY_SIZE = types.WC_ECC_P256_PRIVATE_KEY_SIZE
    WC_SHA256_DIGEST_SIZE = types.WC_SHA256_DIGEST_SIZE
)

// Re-export error type
type WolfSSLError = cgo.WolfSSLError

// ECC functions
func GenerateKey(curve int) ([]byte, []byte, error) {
    return cgo.Wc_ecc_make_key(nil, curve)
}

func Sign(priv []byte, message []byte) ([]byte, error) {
    return cgo.Wc_ecc_sign_hash(priv, message)
}

func Verify(pub []byte, message []byte, sig []byte) bool {
    return cgo.Wc_ecc_verify_hash(sig, message)
}

// SHA256 functions
func Sha256Hash(data []byte) ([32]byte, error) {
    return cgo.Wc_Sha256Hash(data)
}
