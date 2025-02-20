// Package cgo provides low-level C bindings to wolfSSL functions
package cgo

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo/internal"
)

// Re-export error type
type WolfSSLError = internal.WolfSSLError

// Re-export types
type Ecc_key = internal.Ecc_key

// Re-export functions
var (
    Wc_Sha256Hash = internal.Wc_Sha256Hash
    Wc_ecc_init = internal.Wc_ecc_init
    Wc_ecc_free = internal.Wc_ecc_free
    Wc_ecc_make_key = internal.Wc_ecc_make_key
    Wc_ecc_sign_hash = internal.Wc_ecc_sign_hash
    Wc_ecc_verify_hash = internal.Wc_ecc_verify_hash
)

// Re-export constants from internal/types.go
const (
    WC_MD5_DIGEST_SIZE = internal.WC_MD5_DIGEST_SIZE
    WC_SHA_DIGEST_SIZE = internal.WC_SHA_DIGEST_SIZE
    WC_SHA256_DIGEST_SIZE = internal.WC_SHA256_DIGEST_SIZE
    WC_SHA384_DIGEST_SIZE = internal.WC_SHA384_DIGEST_SIZE
    WC_SHA512_DIGEST_SIZE = internal.WC_SHA512_DIGEST_SIZE
    WC_SHA256 = internal.WC_SHA256
    ECC_MAX_SIG_SIZE = internal.ECC_MAX_SIG_SIZE
    ECC_SECP256R1 = internal.ECC_SECP256R1
)
