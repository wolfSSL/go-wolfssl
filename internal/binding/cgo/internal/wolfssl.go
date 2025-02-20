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
// #include <wolfssl/wolfcrypt/kdf.h>
import "C"
import "unsafe"

// Constants for wolfSSL
const (
    // ECC constants
    ECC_SECP256R1 = int(C.ECC_SECP256R1)
    ECC_SECP384R1 = int(C.ECC_SECP384R1)
    ECC_SECP521R1 = int(C.ECC_SECP521R1)

    // Hash types
    WC_HASH_TYPE_SHA256 = int(C.WC_HASH_TYPE_SHA256)
    WC_HASH_TYPE_SHA384 = int(C.WC_HASH_TYPE_SHA384)
    WC_HASH_TYPE_SHA512 = int(C.WC_HASH_TYPE_SHA512)

    // AES constants
    WC_AES_BLOCK_SIZE = int(C.AES_BLOCK_SIZE)
    WC_AES_128_KEY_SIZE = 16
    WC_AES_192_KEY_SIZE = 24
    WC_AES_256_KEY_SIZE = 32

    // GCM constants
    WC_AES_GCM_NONCE_SZ = int(C.GCM_NONCE_MID_SZ)
    WC_AES_GCM_AUTH_SZ = int(C.AES_BLOCK_SIZE)

    // HMAC constants
    WC_HMAC_SHA256_SIZE = int(C.WC_SHA256_DIGEST_SIZE)

    // SHA256 constants
    WC_SHA256_DIGEST_SIZE = int(C.WC_SHA256_DIGEST_SIZE)
    WC_SHA256_BLOCK_SIZE = int(C.WC_SHA256_BLOCK_SIZE)

    // ECC constants
    WC_ECC_P256_SIGNATURE_SIZE = int(C.ECC_MAX_SIG_SIZE)
    WC_ECC_P256_PUBLIC_KEY_SIZE = 65 // X9.63 uncompressed format
    WC_ECC_P256_PRIVATE_KEY_SIZE = 32
)

// HKDF performs HMAC-based Key Derivation Function
func HKDF(hashType int, inputKey []byte, salt []byte, info []byte, outLen int) ([]byte, error) {
    out := make([]byte, outLen)
    ret := C.wc_HKDF(C.int(hashType),
        (*C.byte)(unsafe.Pointer(&inputKey[0])), C.word32(len(inputKey)),
        (*C.byte)(unsafe.Pointer(&salt[0])), C.word32(len(salt)),
        (*C.byte)(unsafe.Pointer(&info[0])), C.word32(len(info)),
        (*C.byte)(unsafe.Pointer(&out[0])), C.word32(outLen))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    return out, nil
}

// ConstantTimeCompare performs constant-time comparison of two byte slices
func ConstantTimeCompare(x, y []byte, n int) int {
    if len(x) < n || len(y) < n {
        return 0
    }
    var v byte
    for i := 0; i < n; i++ {
        v |= x[i] ^ y[i]
    }
    return int(1 & ((v - 1) >> 7))
}

// ConstantTimeSelect returns x if v is 1 and y if v is 0
func ConstantTimeSelect(v, x, y int) int {
    return y ^ (-v & (x ^ y))
}

// ConstantTimeByteEq returns 1 if x == y and 0 otherwise
func ConstantTimeByteEq(x, y uint8) int {
    return int(1 & ((uint32(x^y) - 1) >> 8))
}
