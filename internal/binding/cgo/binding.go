// Package cgo provides CGo bindings for wolfSSL cryptographic functions
package cgo

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo/internal"
)

// Re-export all constants and functions from internal package
var (
    // ECC functions
    GenerateECCKey = internal.GenerateECCKey
    ImportECCPrivateKey = internal.ImportECCPrivateKey
    ImportECCPublicKey = internal.ImportECCPublicKey
    ExportECCPublicKey = internal.ExportECCPublicKey
    SignECC = internal.SignECC
    VerifyECC = internal.VerifyECC
    SharedSecret = internal.SharedSecret
    EccSharedSecret = internal.SharedSecret

    // SHA256 functions
    NewSHA256 = internal.NewSHA256
    SHA256Sum = internal.SHA256Sum

    // AES-GCM functions
    AesGcmEncrypt = internal.AesGcmEncrypt
    AesGcmDecrypt = internal.AesGcmDecrypt
    NewAESGCM = internal.NewAESGCM

    // HMAC functions
    HmacSha256 = internal.HmacSha256
    NewHMAC = internal.NewHMAC
    HmacSha256Init = internal.NewHMAC
    HmacSha256Update = internal.HmacUpdate
    HmacSha256Final = internal.HmacFinal

    // TLS functions
    InitTLS = internal.InitTLS
    CreateTLSContext = internal.CreateTLSContext
    LoadCertificateChain = internal.LoadCertificateChain
    LoadPrivateKey = internal.LoadPrivateKey
    NewTLSConn = internal.NewTLSConn

    // X509 functions
    ParseCertificate = internal.ParseCertificate
    CreateCertificate = internal.CreateCertificate
    ParsePKCS8PrivateKey = internal.ParsePKCS8PrivateKey
    MarshalPKCS8PrivateKey = internal.MarshalPKCS8PrivateKey

    // Random functions
    RandomRead = internal.RandomRead
    Int = internal.Int
    Read = internal.Read

    // HKDF functions
    HKDF = internal.HKDF

    // Constant-time functions
    ConstantTimeCompare = internal.ConstantTimeCompare
    ConstantTimeSelect = internal.ConstantTimeSelect
    ConstantTimeByteEq = internal.ConstantTimeByteEq
)

// Constants re-exported from internal package
const (
    // ECC constants
    ECC_SECP256R1 = internal.ECC_SECP256R1
    ECC_SECP384R1 = internal.ECC_SECP384R1
    ECC_SECP521R1 = internal.ECC_SECP521R1

    // Hash types
    WC_HASH_TYPE_SHA256 = internal.WC_HASH_TYPE_SHA256
    WC_HASH_TYPE_SHA384 = internal.WC_HASH_TYPE_SHA384
    WC_HASH_TYPE_SHA512 = internal.WC_HASH_TYPE_SHA512

    // AES constants
    WC_AES_BLOCK_SIZE = internal.WC_AES_BLOCK_SIZE
    WC_AES_128_KEY_SIZE = internal.WC_AES_128_KEY_SIZE
    WC_AES_192_KEY_SIZE = internal.WC_AES_192_KEY_SIZE
    WC_AES_256_KEY_SIZE = internal.WC_AES_256_KEY_SIZE

    // GCM constants
    WC_AES_GCM_NONCE_SZ = internal.WC_AES_GCM_NONCE_SZ
    WC_AES_GCM_AUTH_SZ = internal.WC_AES_GCM_AUTH_SZ

    // HMAC constants
    WC_HMAC_SHA256_SIZE = internal.WC_HMAC_SHA256_SIZE

    // SHA256 constants
    WC_SHA256_DIGEST_SIZE = internal.WC_SHA256_DIGEST_SIZE
    WC_SHA256_BLOCK_SIZE = internal.WC_SHA256_BLOCK_SIZE

    // ECC constants
    WC_ECC_P256_SIGNATURE_SIZE = internal.WC_ECC_P256_SIGNATURE_SIZE
    WC_ECC_P256_PUBLIC_KEY_SIZE = internal.WC_ECC_P256_PUBLIC_KEY_SIZE
    WC_ECC_P256_PRIVATE_KEY_SIZE = internal.WC_ECC_P256_PRIVATE_KEY_SIZE
)
