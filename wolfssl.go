// Package wolfssl provides FIPS-compliant cryptographic functions
package wolfssl

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
)

// Re-export all types
type (
    Ecc_key = cgo.Ecc_key
    WolfSSLError = cgo.WolfSSLError
)

// Re-export all constants
const (
    WC_SHA256_DIGEST_SIZE = cgo.WC_SHA256_DIGEST_SIZE
    WC_SHA256_BLOCK_SIZE = cgo.WC_SHA256_BLOCK_SIZE
    WC_ECC_P256_SIGNATURE_SIZE = cgo.WC_ECC_P256_SIGNATURE_SIZE
    WC_ECC_P256_PUBLIC_KEY_SIZE = cgo.WC_ECC_P256_PUBLIC_KEY_SIZE
    WC_ECC_P256_PRIVATE_KEY_SIZE = cgo.WC_ECC_P256_PRIVATE_KEY_SIZE
    WC_AES_BLOCK_SIZE = cgo.WC_AES_BLOCK_SIZE
    WC_AES_128_KEY_SIZE = cgo.WC_AES_128_KEY_SIZE
    WC_AES_192_KEY_SIZE = cgo.WC_AES_192_KEY_SIZE
    WC_AES_256_KEY_SIZE = cgo.WC_AES_256_KEY_SIZE
    WC_AES_GCM_NONCE_SZ = cgo.WC_AES_GCM_NONCE_SZ
    WC_AES_GCM_AUTH_SZ = cgo.WC_AES_GCM_AUTH_SZ
    WC_HMAC_SHA256_SIZE = cgo.WC_HMAC_SHA256_SIZE
    WC_POLY1305_MAC_SIZE = cgo.WC_POLY1305_MAC_SIZE
)

// Re-export all functions
var (
    // ECC functions
    GenerateECCKey = cgo.GenerateECCKey
    SignECC = cgo.SignECC
    VerifyECC = cgo.VerifyECC
    ImportPrivate = cgo.ImportPrivate
    ImportPublic = cgo.ImportPublic
    ExportPublic = cgo.ExportPublic
    SharedSecret = cgo.SharedSecret

    // SHA256 functions
    NewSHA256 = cgo.NewSHA256
    SHA256Sum = cgo.SHA256Sum

    // AES-GCM functions
    AesGcmEncrypt = cgo.AesGcmEncrypt
    AesGcmDecrypt = cgo.AesGcmDecrypt

    // HMAC functions
    HmacSha256 = cgo.HmacSha256
    NewHMAC = cgo.NewHMAC
)
