/* mlkem.go
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

// ML-KEM (CRYSTALS-Kyber) wrappers.
//
// Requires wolfSSL built with --enable-mlkem (and optionally
// --enable-experimental if using a pre-release wolfSSL).
// The WOLFSSL_HAVE_MLKEM symbol must be present in wolfssl/options.h.

package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <stdlib.h>
// #ifdef WOLFSSL_HAVE_MLKEM
// #include <wolfssl/wolfcrypt/mlkem.h>
// #endif
//
// /* Stub out the entire API when wolfSSL was built without ML-KEM support. */
// #ifndef WOLFSSL_HAVE_MLKEM
// #define WC_ML_KEM_512   0
// #define WC_ML_KEM_768   1
// #define WC_ML_KEM_1024  2
// #define WC_ML_KEM_512_PUBLIC_KEY_SIZE   1
// #define WC_ML_KEM_512_PRIVATE_KEY_SIZE  1
// #define WC_ML_KEM_512_CIPHER_TEXT_SIZE  1
// #define WC_ML_KEM_768_PUBLIC_KEY_SIZE   1
// #define WC_ML_KEM_768_PRIVATE_KEY_SIZE  1
// #define WC_ML_KEM_768_CIPHER_TEXT_SIZE  1
// #define WC_ML_KEM_1024_PUBLIC_KEY_SIZE  1
// #define WC_ML_KEM_1024_PRIVATE_KEY_SIZE 1
// #define WC_ML_KEM_1024_CIPHER_TEXT_SIZE 1
// #define WC_ML_KEM_SS_SZ                 1
// struct MlKemKey { int dummy; };
// typedef struct MlKemKey MlKemKey;
// static MlKemKey* wc_MlKemKey_New(int type, void* heap, int devId)
//     { (void)type; (void)heap; (void)devId; return NULL; }
// static int wc_MlKemKey_Delete(MlKemKey* key, MlKemKey** key_p)
//     { (void)key; (void)key_p; return -174; }
// static int wc_MlKemKey_Free(MlKemKey* key)
//     { (void)key; return -174; }
// static int wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng)
//     { (void)key; (void)rng; return -174; }
// static int wc_MlKemKey_EncodePublicKey(MlKemKey* key, unsigned char* out, word32 len)
//     { (void)key; (void)out; (void)len; return -174; }
// static int wc_MlKemKey_EncodePrivateKey(MlKemKey* key, unsigned char* out, word32 len)
//     { (void)key; (void)out; (void)len; return -174; }
// static int wc_MlKemKey_DecodePublicKey(MlKemKey* key, const unsigned char* in, word32 len)
//     { (void)key; (void)in; (void)len; return -174; }
// static int wc_MlKemKey_DecodePrivateKey(MlKemKey* key, const unsigned char* in, word32 len)
//     { (void)key; (void)in; (void)len; return -174; }
// static int wc_MlKemKey_Encapsulate(MlKemKey* key, unsigned char* ct, unsigned char* ss, WC_RNG* rng)
//     { (void)key; (void)ct; (void)ss; (void)rng; return -174; }
// static int wc_MlKemKey_Decapsulate(MlKemKey* key, unsigned char* ss, const unsigned char* ct, word32 ctSz)
//     { (void)key; (void)ss; (void)ct; (void)ctSz; return -174; }
// #endif
import "C"
import (
    "errors"
)

// ML-KEM size constants (raw byte lengths, not DER-encoded).
const (
    MLKEM_512_PUB_SIZE        = int(C.WC_ML_KEM_512_PUBLIC_KEY_SIZE)
    MLKEM_512_PRIV_SIZE       = int(C.WC_ML_KEM_512_PRIVATE_KEY_SIZE)
    MLKEM_512_CIPHERTEXT_SIZE = int(C.WC_ML_KEM_512_CIPHER_TEXT_SIZE)
    MLKEM_512_SHARED_SIZE     = int(C.WC_ML_KEM_SS_SZ)

    MLKEM_768_PUB_SIZE        = int(C.WC_ML_KEM_768_PUBLIC_KEY_SIZE)
    MLKEM_768_PRIV_SIZE       = int(C.WC_ML_KEM_768_PRIVATE_KEY_SIZE)
    MLKEM_768_CIPHERTEXT_SIZE = int(C.WC_ML_KEM_768_CIPHER_TEXT_SIZE)
    MLKEM_768_SHARED_SIZE     = int(C.WC_ML_KEM_SS_SZ)

    MLKEM_1024_PUB_SIZE        = int(C.WC_ML_KEM_1024_PUBLIC_KEY_SIZE)
    MLKEM_1024_PRIV_SIZE       = int(C.WC_ML_KEM_1024_PRIVATE_KEY_SIZE)
    MLKEM_1024_CIPHERTEXT_SIZE = int(C.WC_ML_KEM_1024_CIPHER_TEXT_SIZE)
    MLKEM_1024_SHARED_SIZE     = int(C.WC_ML_KEM_SS_SZ)
)

// MlKemLevel selects between the three ML-KEM parameter sets.
type MlKemLevel int

const (
    MlKemLevel512  MlKemLevel = C.WC_ML_KEM_512
    MlKemLevel768  MlKemLevel = C.WC_ML_KEM_768
    MlKemLevel1024 MlKemLevel = C.WC_ML_KEM_1024
)

// pubPrivSizes returns (pubSz, privSz, ctSz, ssSz) for the given level.
func mlkemSizes(level MlKemLevel) (pub, priv, ct, ss int, err error) {
    switch level {
    case MlKemLevel512:
        return MLKEM_512_PUB_SIZE, MLKEM_512_PRIV_SIZE, MLKEM_512_CIPHERTEXT_SIZE, MLKEM_512_SHARED_SIZE, nil
    case MlKemLevel768:
        return MLKEM_768_PUB_SIZE, MLKEM_768_PRIV_SIZE, MLKEM_768_CIPHERTEXT_SIZE, MLKEM_768_SHARED_SIZE, nil
    case MlKemLevel1024:
        return MLKEM_1024_PUB_SIZE, MLKEM_1024_PRIV_SIZE, MLKEM_1024_CIPHERTEXT_SIZE, MLKEM_1024_SHARED_SIZE, nil
    default:
        return 0, 0, 0, 0, errors.New("wolfSSL: unknown MlKemLevel")
    }
}

// mlkemNewKey allocates a new MlKemKey via wolfSSL's own allocator.
func mlkemNewKey(level MlKemLevel) (*C.MlKemKey, error) {
    key := C.wc_MlKemKey_New(C.int(level), nil, C.int(C.INVALID_DEVID))
    if key == nil {
        return nil, errors.New("wolfSSL: wc_MlKemKey_New failed (WOLFSSL_HAVE_MLKEM not enabled?)")
    }
    return key, nil
}

func mlkemFreeKey(key *C.MlKemKey) {
    C.wc_MlKemKey_Delete(key, nil)
}

// mlkemNewRng allocates and initialises a WC_RNG via wolfSSL's own allocator.
func mlkemNewRng() (*C.WC_RNG, error) {
    rng := C.wc_rng_new(nil, 0, nil)
    if rng == nil {
        return nil, errors.New("wolfSSL: wc_rng_new failed")
    }
    return rng, nil
}

// MlKemGenerateKey generates an ML-KEM key pair at the requested security
// level.  publicKey and privateKey are raw (non-DER) byte slices whose lengths
// match the MLKEM_*_PUB_SIZE / MLKEM_*_PRIV_SIZE constants.
func MlKemGenerateKey(level MlKemLevel) (publicKey, privateKey []byte, err error) {
    pubSz, privSz, _, _, err := mlkemSizes(level)
    if err != nil {
        return nil, nil, err
    }

    key, err := mlkemNewKey(level)
    if err != nil {
        return nil, nil, err
    }
    defer mlkemFreeKey(key)

    rng, err := mlkemNewRng()
    if err != nil {
        return nil, nil, err
    }
    defer C.wc_rng_free(rng)

    if ret := C.wc_MlKemKey_MakeKey(key, rng); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_MlKemKey_MakeKey failed")
    }

    pubBuf := make([]byte, pubSz)
    if ret := C.wc_MlKemKey_EncodePublicKey(key,
        (*C.uchar)(&pubBuf[0]), C.word32(pubSz)); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_MlKemKey_EncodePublicKey failed")
    }

    privBuf := make([]byte, privSz)
    if ret := C.wc_MlKemKey_EncodePrivateKey(key,
        (*C.uchar)(&privBuf[0]), C.word32(privSz)); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_MlKemKey_EncodePrivateKey failed")
    }

    return pubBuf, privBuf, nil
}

// MlKemEncapsulate generates a shared secret and encapsulates it under
// publicKey.  Returns (ciphertext, sharedSecret, error).
func MlKemEncapsulate(level MlKemLevel, publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
    pubSz, _, ctSz, ssSz, err := mlkemSizes(level)
    if err != nil {
        return nil, nil, err
    }
    if len(publicKey) != pubSz {
        return nil, nil, errors.New("wolfSSL: MlKemEncapsulate: wrong public key length")
    }

    key, err := mlkemNewKey(level)
    if err != nil {
        return nil, nil, err
    }
    defer mlkemFreeKey(key)

    if ret := C.wc_MlKemKey_DecodePublicKey(key,
        (*C.uchar)(&publicKey[0]), C.word32(pubSz)); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_MlKemKey_DecodePublicKey failed")
    }

    rng, err := mlkemNewRng()
    if err != nil {
        return nil, nil, err
    }
    defer C.wc_rng_free(rng)

    ctBuf := make([]byte, ctSz)
    ssBuf := make([]byte, ssSz)

    if ret := C.wc_MlKemKey_Encapsulate(key,
        (*C.uchar)(&ctBuf[0]),
        (*C.uchar)(&ssBuf[0]),
        rng); ret != 0 {
        return nil, nil, errors.New("wolfSSL: wc_MlKemKey_Encapsulate failed")
    }

    return ctBuf, ssBuf, nil
}

// MlKemDecapsulate recovers the shared secret from ciphertext using
// privateKey.
func MlKemDecapsulate(level MlKemLevel, privateKey, ciphertext []byte) (sharedSecret []byte, err error) {
    _, privSz, ctSz, ssSz, err := mlkemSizes(level)
    if err != nil {
        return nil, err
    }
    if len(privateKey) != privSz {
        return nil, errors.New("wolfSSL: MlKemDecapsulate: wrong private key length")
    }
    if len(ciphertext) != ctSz {
        return nil, errors.New("wolfSSL: MlKemDecapsulate: wrong ciphertext length")
    }

    key, err := mlkemNewKey(level)
    if err != nil {
        return nil, err
    }
    defer mlkemFreeKey(key)

    if ret := C.wc_MlKemKey_DecodePrivateKey(key,
        (*C.uchar)(&privateKey[0]), C.word32(privSz)); ret != 0 {
        return nil, errors.New("wolfSSL: wc_MlKemKey_DecodePrivateKey failed")
    }

    ssBuf := make([]byte, ssSz)
    if ret := C.wc_MlKemKey_Decapsulate(key,
        (*C.uchar)(&ssBuf[0]),
        (*C.uchar)(&ciphertext[0]),
        C.word32(ctSz)); ret != 0 {
        return nil, errors.New("wolfSSL: wc_MlKemKey_Decapsulate failed")
    }

    return ssBuf, nil
}
