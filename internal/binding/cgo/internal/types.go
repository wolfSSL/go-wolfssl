package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/hash.h>
import "C"

const (
    // Hash sizes
    WC_MD5_DIGEST_SIZE = int(C.WC_MD5_DIGEST_SIZE)
    WC_SHA_DIGEST_SIZE = int(C.WC_SHA_DIGEST_SIZE)
    WC_SHA256_DIGEST_SIZE = int(C.WC_SHA256_DIGEST_SIZE)
    WC_SHA384_DIGEST_SIZE = int(C.WC_SHA384_DIGEST_SIZE)
    WC_SHA512_DIGEST_SIZE = int(C.WC_SHA512_DIGEST_SIZE)
    WC_SHA256 = int(C.WC_SHA256)

    // ECC sizes
    ECC_MAX_SIG_SIZE = int(C.ECC_MAX_SIG_SIZE)
    ECC_SECP256R1 = int(C.ECC_SECP256R1)
)

// Re-export types
type Ecc_key = C.struct_ecc_key
