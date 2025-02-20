// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/settings.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/sha256.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/hmac.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
import "C"

// Re-export all functions
var (
    // ECC functions
    GenerateECCKey = GenerateECCKey
    SignECC = SignECC
    VerifyECC = VerifyECC
    ImportPrivate = ImportPrivate
    ImportPublic = ImportPublic
    ExportPublic = ExportPublic
    SharedSecret = SharedSecret

    // SHA256 functions
    NewSHA256 = NewSHA256
    SHA256Sum = SHA256Sum

    // AES-GCM functions
    AesGcmEncrypt = AesGcmEncrypt
    AesGcmDecrypt = AesGcmDecrypt

    // HMAC functions
    HmacSha256 = HmacSha256
    NewHMAC = NewHMAC

    // Random functions
    RandomRead = RandomRead
    Int = Int

    // HKDF functions
    HKDF = HKDF
)
