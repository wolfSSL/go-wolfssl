// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/settings.h>
// #include <wolfssl/wolfcrypt/error.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/sha256.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/hmac.h>
import "C"

// Constants for wolfSSL
const (
    WC_SHA256_DIGEST_SIZE = int(C.WC_SHA256_DIGEST_SIZE)
    WC_SHA256_BLOCK_SIZE = int(C.WC_SHA256_BLOCK_SIZE)
    WC_AES_BLOCK_SIZE = int(C.AES_BLOCK_SIZE)
    WC_HMAC_SHA256_SIZE = int(C.WC_SHA256_DIGEST_SIZE)
    ECC_MAX_SIG_SIZE = int(C.ECC_MAX_SIG_SIZE)
    ECC_SECP256R1 = int(C.ECC_SECP256R1)
)
