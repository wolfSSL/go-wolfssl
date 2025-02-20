// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/ecc.h>
import "C"
import "unsafe"

// GenerateECCKey generates a new ECC key pair
func GenerateECCKey(curve int) (pub, priv []byte, err error) {
    var key C.ecc_key
    ret := C.wc_ecc_init(&key)
    if ret != 0 {
        return nil, nil, WolfSSLError(ret)
    }
    defer C.wc_ecc_free(&key)

    var rng C.WC_RNG
    ret = C.wc_InitRng(&rng)
    if ret != 0 {
        return nil, nil, WolfSSLError(ret)
    }
    defer C.wc_FreeRng(&rng)

    ret = C.wc_ecc_make_key(&rng, WC_ECC_P256_PRIVATE_KEY_SIZE, &key)
    if ret != 0 {
        return nil, nil, WolfSSLError(ret)
    }

    // Export public key
    pubKey := make([]byte, WC_ECC_P256_PUBLIC_KEY_SIZE)
    pubKeySz := C.word32(len(pubKey))
    ret = C.wc_ecc_export_x963(&key, (*C.byte)(unsafe.Pointer(&pubKey[0])), &pubKeySz)
    if ret != 0 {
        return nil, nil, WolfSSLError(ret)
    }

    // Export private key
    privKey := make([]byte, WC_ECC_P256_PRIVATE_KEY_SIZE)
    privKeySz := C.word32(len(privKey))
    ret = C.wc_ecc_export_private_only(&key, (*C.byte)(unsafe.Pointer(&privKey[0])), &privKeySz)
    if ret != 0 {
        return nil, nil, WolfSSLError(ret)
    }

    return pubKey[:pubKeySz], privKey[:privKeySz], nil
}

// SignECC signs a message using an ECC private key
func SignECC(priv []byte, msg []byte) ([]byte, error) {
    var key C.ecc_key
    ret := C.wc_ecc_init(&key)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_ecc_free(&key)

    ret = C.wc_ecc_import_private_key_ex(
        (*C.byte)(unsafe.Pointer(&priv[0])),
        C.word32(len(priv)),
        nil,
        0,
        &key,
        C.ECC_SECP256R1,
    )
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    var rng C.WC_RNG
    ret = C.wc_InitRng(&rng)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_FreeRng(&rng)

    sig := make([]byte, WC_ECC_P256_SIGNATURE_SIZE)
    sigSz := C.word32(len(sig))

    ret = C.wc_ecc_sign_hash(
        (*C.byte)(unsafe.Pointer(&msg[0])),
        C.word32(len(msg)),
        (*C.byte)(unsafe.Pointer(&sig[0])),
        &sigSz,
        &rng,
        &key,
    )
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    return sig[:sigSz], nil
}

// VerifyECC verifies an ECC signature
func VerifyECC(pub []byte, msg []byte, sig []byte) (bool, error) {
    var key C.ecc_key
    ret := C.wc_ecc_init(&key)
    if ret != 0 {
        return false, WolfSSLError(ret)
    }
    defer C.wc_ecc_free(&key)

    ret = C.wc_ecc_import_x963_ex(
        (*C.byte)(unsafe.Pointer(&pub[0])),
        C.word32(len(pub)),
        &key,
        C.ECC_SECP256R1,
    )
    if ret != 0 {
        return false, WolfSSLError(ret)
    }

    var verify C.int
    ret = C.wc_ecc_verify_hash(
        (*C.byte)(unsafe.Pointer(&sig[0])),
        C.word32(len(sig)),
        (*C.byte)(unsafe.Pointer(&msg[0])),
        C.word32(len(msg)),
        &verify,
        &key,
    )
    if ret != 0 {
        return false, WolfSSLError(ret)
    }

    return verify == 1, nil
}

// ImportPrivate imports a private key
func ImportPrivate(curve int, priv []byte) (*C.ecc_key, error) {
    var key C.ecc_key
    ret := C.wc_ecc_init(&key)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    ret = C.wc_ecc_import_private_key_ex(
        (*C.byte)(unsafe.Pointer(&priv[0])),
        C.word32(len(priv)),
        nil,
        0,
        &key,
        C.int(curve),
    )
    if ret != 0 {
        C.wc_ecc_free(&key)
        return nil, WolfSSLError(ret)
    }

    return &key, nil
}

// ImportPublic imports a public key
func ImportPublic(curve int, pub []byte) (*C.ecc_key, error) {
    var key C.ecc_key
    ret := C.wc_ecc_init(&key)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    ret = C.wc_ecc_import_x963_ex(
        (*C.byte)(unsafe.Pointer(&pub[0])),
        C.word32(len(pub)),
        &key,
        C.int(curve),
    )
    if ret != 0 {
        C.wc_ecc_free(&key)
        return nil, WolfSSLError(ret)
    }

    return &key, nil
}

// ExportPublic exports a public key
func ExportPublic(key *C.ecc_key) ([]byte, error) {
    pub := make([]byte, WC_ECC_P256_PUBLIC_KEY_SIZE)
    pubSz := C.word32(len(pub))

    ret := C.wc_ecc_export_x963(key, (*C.byte)(unsafe.Pointer(&pub[0])), &pubSz)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    return pub[:pubSz], nil
}
