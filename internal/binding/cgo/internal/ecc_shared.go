// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/ecc.h>
import "C"
import "unsafe"

// SharedSecret computes a shared secret between two ECC keys
func SharedSecret(privKey, pubKey *C.ecc_key) ([]byte, error) {
    var rng C.WC_RNG
    ret := C.wc_InitRng(&rng)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_FreeRng(&rng)

    secret := make([]byte, WC_ECC_P256_PRIVATE_KEY_SIZE)
    secretSz := C.word32(len(secret))

    ret = C.wc_ecc_shared_secret(privKey, pubKey, (*C.byte)(unsafe.Pointer(&secret[0])), &secretSz)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    return secret[:secretSz], nil
}
