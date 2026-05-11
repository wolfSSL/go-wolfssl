//go:build dilithium

/* dilithium.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

// ML-DSA (CRYSTALS-Dilithium) wrappers.
//
// Build tag: this file is only compiled when the "dilithium" build tag is
// provided, because the system wolfSSL must have been built with
// --enable-dilithium --enable-experimental.
//
// To build and test:
//
//	go build -tags dilithium .
//	go test -tags dilithium -count=1 ./...

package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/dilithium.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <stdlib.h>
import "C"
import (
    "errors"
    "unsafe"
)

// ML-DSA size constants.  Level numbers follow the NIST naming:
//   - ML-DSA-44  corresponds to wolfSSL level 2 (DILITHIUM_LEVEL2_*)
//   - ML-DSA-65  corresponds to wolfSSL level 3 (DILITHIUM_LEVEL3_*)
//   - ML-DSA-87  corresponds to wolfSSL level 5 (DILITHIUM_LEVEL5_*)
const (
    MLDSA_44_PUB_SIZE  = int(C.ML_DSA_LEVEL2_PUB_KEY_SIZE)
    MLDSA_44_PRIV_SIZE = int(C.ML_DSA_LEVEL2_PRV_KEY_SIZE)
    MLDSA_44_SIG_SIZE  = int(C.ML_DSA_LEVEL2_SIG_SIZE)

    MLDSA_65_PUB_SIZE  = int(C.ML_DSA_LEVEL3_PUB_KEY_SIZE)
    MLDSA_65_PRIV_SIZE = int(C.ML_DSA_LEVEL3_PRV_KEY_SIZE)
    MLDSA_65_SIG_SIZE  = int(C.ML_DSA_LEVEL3_SIG_SIZE)

    MLDSA_87_PUB_SIZE  = int(C.ML_DSA_LEVEL5_PUB_KEY_SIZE)
    MLDSA_87_PRIV_SIZE = int(C.ML_DSA_LEVEL5_PRV_KEY_SIZE)
    MLDSA_87_SIG_SIZE  = int(C.ML_DSA_LEVEL5_SIG_SIZE)
)

// MlDsaLevel selects the ML-DSA security level.
// wolfSSL uses byte values 2, 3, 5 for its internal level representation.
type MlDsaLevel byte

const (
    MlDsaLevel44 MlDsaLevel = 2 // ML-DSA-44
    MlDsaLevel65 MlDsaLevel = 3 // ML-DSA-65
    MlDsaLevel87 MlDsaLevel = 5 // ML-DSA-87
)

func mldsaSizes(level MlDsaLevel) (pub, priv, sig int, err error) {
    switch level {
    case MlDsaLevel44:
        return MLDSA_44_PUB_SIZE, MLDSA_44_PRIV_SIZE, MLDSA_44_SIG_SIZE, nil
    case MlDsaLevel65:
        return MLDSA_65_PUB_SIZE, MLDSA_65_PRIV_SIZE, MLDSA_65_SIG_SIZE, nil
    case MlDsaLevel87:
        return MLDSA_87_PUB_SIZE, MLDSA_87_PRIV_SIZE, MLDSA_87_SIG_SIZE, nil
    default:
        return 0, 0, 0, errors.New("wolfSSL: unknown MlDsaLevel")
    }
}

// dilithiumNewKey allocates and initialises a dilithium_key at the given level.
func dilithiumNewKey(level MlDsaLevel) (*C.dilithium_key, error) {
    key := (*C.dilithium_key)(C.calloc(1, C.sizeof_dilithium_key))
    if key == nil {
        return nil, errors.New("wolfSSL: calloc dilithium_key failed")
    }
    if ret := C.wc_dilithium_init(key); ret != 0 {
        C.free(unsafe.Pointer(key))
        return nil, errors.New("wolfSSL: wc_dilithium_init failed")
    }
    if ret := C.wc_dilithium_set_level(key, C.byte(level)); ret != 0 {
        C.wc_dilithium_free(key)
        C.free(unsafe.Pointer(key))
        return nil, errors.New("wolfSSL: wc_dilithium_set_level failed")
    }
    return key, nil
}

func dilithiumFreeKey(key *C.dilithium_key) {
    if key != nil {
        C.wc_dilithium_free(key)
        C.free(unsafe.Pointer(key))
    }
}

// MlDsaGenerateKey generates an ML-DSA key pair.
func MlDsaGenerateKey(level MlDsaLevel) (publicKey, privateKey []byte, err error) {
    pubSz, privSz, _, err := mldsaSizes(level)
    if err != nil {
        return nil, nil, err
    }

    key, err := dilithiumNewKey(level)
    if err != nil {
        return nil, nil, err
    }
    defer dilithiumFreeKey(key)

    rng := C.wc_rng_new(nil, 0, nil)
    if rng == nil {
        return nil, nil, errors.New("wolfSSL: wc_rng_new failed")
    }
    defer C.wc_rng_free(rng)

    if ret := C.wc_dilithium_make_key(key, rng); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_dilithium_make_key failed")
    }

    pubBuf := make([]byte, pubSz)
    pubLen := C.word32(pubSz)
    if ret := C.wc_dilithium_export_public(key,
        (*C.byte)(&pubBuf[0]), &pubLen); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_dilithium_export_public failed")
    }
    pubBuf = pubBuf[:pubLen]

    privBuf := make([]byte, privSz)
    privLen := C.word32(privSz)
    if ret := C.wc_dilithium_export_private(key,
        (*C.byte)(&privBuf[0]), &privLen); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_dilithium_export_private failed")
    }
    privBuf = privBuf[:privLen]

    return pubBuf, privBuf, nil
}

// MlDsaSign signs msg with privateKey and returns the signature.
func MlDsaSign(level MlDsaLevel, privateKey, msg []byte) (signature []byte, err error) {
    _, privSz, sigSz, err := mldsaSizes(level)
    if err != nil {
        return nil, err
    }
    if len(privateKey) != privSz {
        return nil, errors.New("wolfSSL: MlDsaSign: wrong private key length")
    }
    if len(msg) == 0 {
        return nil, errors.New("wolfSSL: MlDsaSign: empty message")
    }

    key, err := dilithiumNewKey(level)
    if err != nil {
        return nil, err
    }
    defer dilithiumFreeKey(key)

    if ret := C.wc_dilithium_import_private(
        (*C.byte)(&privateKey[0]), C.word32(privSz), key); ret != 0 {
        return nil, errors.New("wolfSSL: wc_dilithium_import_private failed")
    }

    rng := C.wc_rng_new(nil, 0, nil)
    if rng == nil {
        return nil, errors.New("wolfSSL: wc_rng_new failed")
    }
    defer C.wc_rng_free(rng)

    sigBuf := make([]byte, sigSz)
    sigLen := C.word32(sigSz)
    // Use the FIPS-204 context API with ctx=NULL, ctxLen=0 (empty context).
    ret := C.wc_dilithium_sign_ctx_msg(
        nil, 0,
        (*C.byte)(&msg[0]), C.word32(len(msg)),
        (*C.byte)(&sigBuf[0]), &sigLen,
        key, rng)
    if ret != 0 {
        return nil, errors.New("wolfSSL: wc_dilithium_sign_ctx_msg failed")
    }

    return sigBuf[:sigLen], nil
}

// MlDsaVerify verifies signature over msg using publicKey.
// Returns (true, nil) on valid signature, (false, nil) on invalid.
func MlDsaVerify(level MlDsaLevel, publicKey, msg, signature []byte) (bool, error) {
    pubSz, _, _, err := mldsaSizes(level)
    if err != nil {
        return false, err
    }
    if len(publicKey) != pubSz {
        return false, errors.New("wolfSSL: MlDsaVerify: wrong public key length")
    }
    if len(msg) == 0 {
        return false, errors.New("wolfSSL: MlDsaVerify: empty message")
    }
    if len(signature) == 0 {
        return false, errors.New("wolfSSL: MlDsaVerify: empty signature")
    }

    key, err := dilithiumNewKey(level)
    if err != nil {
        return false, err
    }
    defer dilithiumFreeKey(key)

    if ret := C.wc_dilithium_import_public(
        (*C.byte)(&publicKey[0]), C.word32(pubSz), key); ret != 0 {
        return false, errors.New("wolfSSL: wc_dilithium_import_public failed")
    }

    var res C.int
    ret := C.wc_dilithium_verify_ctx_msg(
        (*C.byte)(&signature[0]), C.word32(len(signature)),
        nil, 0,
        (*C.byte)(&msg[0]), C.word32(len(msg)),
        &res, key)
    if ret != 0 {
        // A non-zero return typically means the signature is invalid.
        return false, nil
    }

    return res == 1, nil
}
