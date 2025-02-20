// Package cgo provides CGo bindings for wolfSSL cryptographic functions
package cgo

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo/internal"
)

// Re-export all types
type (
    Ecc_key = internal.Ecc_key
    WolfSSLError = internal.WolfSSLError
)

// Re-export all constants
const (
    WC_SHA256_DIGEST_SIZE = internal.WC_SHA256_DIGEST_SIZE
    WC_SHA256_BLOCK_SIZE = internal.WC_SHA256_BLOCK_SIZE
    WC_ECC_P256_SIGNATURE_SIZE = internal.WC_ECC_P256_SIGNATURE_SIZE
    WC_ECC_P256_PUBLIC_KEY_SIZE = internal.WC_ECC_P256_PUBLIC_KEY_SIZE
    WC_ECC_P256_PRIVATE_KEY_SIZE = internal.WC_ECC_P256_PRIVATE_KEY_SIZE
    WC_AES_BLOCK_SIZE = internal.WC_AES_BLOCK_SIZE
    WC_AES_128_KEY_SIZE = internal.WC_AES_128_KEY_SIZE
    WC_AES_192_KEY_SIZE = internal.WC_AES_192_KEY_SIZE
    WC_AES_256_KEY_SIZE = internal.WC_AES_256_KEY_SIZE
    WC_AES_GCM_NONCE_SZ = internal.WC_AES_GCM_NONCE_SZ
    WC_AES_GCM_AUTH_SZ = internal.WC_AES_GCM_AUTH_SZ
    WC_HMAC_SHA256_SIZE = internal.WC_HMAC_SHA256_SIZE
    WC_POLY1305_MAC_SIZE = internal.WC_POLY1305_MAC_SIZE
)

// Re-export all functions
var (
    // ECC functions
    GenerateECCKey = internal.GenerateECCKey
    SignECC = internal.SignECC
    VerifyECC = internal.VerifyECC
    ImportPrivate = internal.ImportPrivate
    ImportPublic = internal.ImportPublic
    ExportPublic = internal.ExportPublic
    SharedSecret = internal.SharedSecret

    // SHA256 functions
    NewSHA256 = internal.NewSHA256
    SHA256Sum = internal.SHA256Sum

    // AES-GCM functions
    AesGcmEncrypt = internal.AesGcmEncrypt
    AesGcmDecrypt = internal.AesGcmDecrypt

    // HMAC functions
    HmacSha256 = internal.HmacSha256
    NewHMAC = internal.NewHMAC
)
