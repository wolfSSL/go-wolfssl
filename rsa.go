/* rsa.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package wolfSSL

// #include <stdlib.h>
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/rsa.h>
// #include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/hash.h>
// #include <wolfssl/wolfcrypt/types.h>
// #ifdef NO_RSA
// typedef struct RsaKey {} RsaKey;
// int wc_InitRsaKey(RsaKey* key, void* heap) { (void)key; (void)heap; return -174; }
// int wc_FreeRsaKey(RsaKey* key)             { (void)key; return -174; }
// int wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz,
//                              const byte* e, word32 eSz, RsaKey* key) {
//     (void)n; (void)nSz; (void)e; (void)eSz; (void)key; return -174;
// }
// int wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
//                            RsaKey* key, word32 inSz) {
//     (void)input; (void)inOutIdx; (void)key; (void)inSz; return -174;
// }
// int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng) {
//     (void)key; (void)size; (void)e; (void)rng; return -174;
// }
// int wc_RsaFlattenPublicKey(RsaKey* key, byte* a, word32* aSz,
//                            byte* b, word32* bSz) {
//     (void)key; (void)a; (void)aSz; (void)b; (void)bSz; return -174;
// }
// int wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out, word32 outLen,
//                    RsaKey* key, WC_RNG* rng) {
//     (void)in; (void)inLen; (void)out; (void)outLen; (void)key; (void)rng;
//     return -174;
// }
// int wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out, word32 outLen,
//                      RsaKey* key) {
//     (void)in; (void)inLen; (void)out; (void)outLen; (void)key; return -174;
// }
// #endif
// #if defined(NO_ASN) && defined(NO_DH) && !defined(HAVE_ECC)
// int wc_HashGetOID(enum wc_HashType hash_type) { (void)hash_type; return -174; }
// #endif
// #ifdef NO_HASH_WRAPPER
// int wc_HashGetDigestSize(enum wc_HashType hash_type) { (void)hash_type; return -174; }
// #endif
// #if !defined(NO_RSA) && !defined(WOLFSSL_KEY_GEN)
// int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng) {
//     (void)key; (void)size; (void)e; (void)rng; return -174;
// }
// #endif
// #if !defined(WC_RSA_PSS) || defined(NO_RSA)
// #define WC_MGF1SHA256 1
// #define WC_MGF1SHA384 2
// #define WC_MGF1SHA512 3
// int wc_RsaPSS_VerifyCheck(const byte* in, word32 inLen,
//                           byte* out, word32 outLen,
//                           const byte* digest, word32 digestLen,
//                           int hash, int mgf, RsaKey* key) {
//     (void)in; (void)inLen; (void)out; (void)outLen;
//     (void)digest; (void)digestLen; (void)hash; (void)mgf; (void)key;
//     return -174;
// }
// int wc_RsaPSS_Sign_ex(const byte* in, word32 inLen, byte* out,
//                       word32 outLen, int hash, int mgf, int saltLen,
//                       RsaKey* key, WC_RNG* rng) {
//     (void)in; (void)inLen; (void)out; (void)outLen;
//     (void)hash; (void)mgf; (void)saltLen; (void)key; (void)rng;
//     return -174;
// }
// #endif
import "C"
import "unsafe"

type RsaKey = C.struct_RsaKey

const (
    WC_HASH_TYPE_SHA256 = int(C.WC_HASH_TYPE_SHA256)
    WC_HASH_TYPE_SHA384 = int(C.WC_HASH_TYPE_SHA384)
    WC_HASH_TYPE_SHA512 = int(C.WC_HASH_TYPE_SHA512)
)


const (
    WC_MGF1SHA256 = int(C.WC_MGF1SHA256)
    WC_MGF1SHA384 = int(C.WC_MGF1SHA384)
    WC_MGF1SHA512 = int(C.WC_MGF1SHA512)
)

func Wc_InitRsaKey(key *C.struct_RsaKey) int {
    return int(C.wc_InitRsaKey(key, nil))
}

func Wc_FreeRsaKey(key *C.struct_RsaKey) int {
    return int(C.wc_FreeRsaKey(key))
}

// Wc_RsaPublicKeyDecodeRaw imports a public key from the raw modulus
func Wc_RsaPublicKeyDecodeRaw(n []byte, e []byte, key *C.struct_RsaKey) int {
    if len(n) == 0 || len(e) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_RsaPublicKeyDecodeRaw(
        (*C.byte)(unsafe.Pointer(&n[0])), C.word32(len(n)),
        (*C.byte)(unsafe.Pointer(&e[0])), C.word32(len(e)),
        key))
}

// Wc_RsaPrivateKeyDecode imports an RSA private key from a PKCS#1
// DER blob
func Wc_RsaPrivateKeyDecode(der []byte, key *C.struct_RsaKey) int {
    if len(der) == 0 {
        return BAD_FUNC_ARG
    }
    var idx C.word32 = 0
    return int(C.wc_RsaPrivateKeyDecode(
        (*C.byte)(unsafe.Pointer(&der[0])), &idx, key, C.word32(len(der))))
}

// Wc_RsaSSL_Sign produces an RSASSA-PKCS1-v1_5 signature.
func Wc_RsaSSL_Sign(in []byte, out []byte, key *C.struct_RsaKey, rng *C.struct_WC_RNG) int {
    if len(in) == 0 || len(out) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_RsaSSL_Sign(
        (*C.byte)(unsafe.Pointer(&in[0])), C.word32(len(in)),
        (*C.byte)(unsafe.Pointer(&out[0])), C.word32(len(out)),
        key, rng))
}

// Wc_RsaSSL_Verify verifies an RSASSA-PKCS1-v1_5 signature
func Wc_RsaSSL_Verify(sig []byte, out []byte, key *C.struct_RsaKey) int {
    if len(sig) == 0 || len(out) < len(sig) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_RsaSSL_Verify(
        (*C.byte)(unsafe.Pointer(&sig[0])), C.word32(len(sig)),
        (*C.byte)(unsafe.Pointer(&out[0])), C.word32(len(out)),
        key))
}

const MAX_ENCODED_SIG_SZ = int(C.MAX_ENCODED_SIG_SZ)

func Wc_HashGetOID(hashType int) int {
    return int(C.wc_HashGetOID(C.enum_wc_HashType(hashType)))
}

// Wc_HashGetDigestSize returns the digest output size in bytes for the
// given hash type, or a negative wolfCrypt error code if the hash type
// is unsupported.
func Wc_HashGetDigestSize(hashType int) int {
    return int(C.wc_HashGetDigestSize(C.enum_wc_HashType(hashType)))
}

func Wc_EncodeSignature(out []byte, digest []byte, hashOID int) int {
    if len(out) == 0 || len(digest) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_EncodeSignature(
        (*C.byte)(unsafe.Pointer(&out[0])),
        (*C.byte)(unsafe.Pointer(&digest[0])), C.word32(len(digest)),
        C.int(hashOID)))
}

func Wc_MakeRsaKey(key *C.struct_RsaKey, size int, e int64, rng *C.struct_WC_RNG) int {
    return int(C.wc_MakeRsaKey(key, C.int(size), C.long(e), rng))
}

func Wc_RsaPSS_VerifyCheck(sig []byte, out []byte, digest []byte,
    hashType int, mgf int, key *C.struct_RsaKey) int {
    if len(sig) == 0 || len(out) < len(sig) || len(digest) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_RsaPSS_VerifyCheck(
        (*C.byte)(unsafe.Pointer(&sig[0])), C.word32(len(sig)),
        (*C.byte)(unsafe.Pointer(&out[0])), C.word32(len(out)),
        (*C.byte)(unsafe.Pointer(&digest[0])), C.word32(len(digest)),
        C.enum_wc_HashType(hashType), C.int(mgf), key))
}

func Wc_RsaPSS_Sign_ex(digest []byte, sig []byte,
    hashType int, mgf int, saltLen int,
    key *C.struct_RsaKey, rng *C.struct_WC_RNG) int {
    if len(digest) == 0 || len(sig) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_RsaPSS_Sign_ex(
        (*C.byte)(unsafe.Pointer(&digest[0])), C.word32(len(digest)),
        (*C.byte)(unsafe.Pointer(&sig[0])), C.word32(len(sig)),
        C.enum_wc_HashType(hashType), C.int(mgf), C.int(saltLen),
        key, rng))
}

// Wc_RsaFlattenPublicKey exports the public exponent e and modulus n
// from key as raw big-endian byte slices. eSz and nSz are in/out
func Wc_RsaFlattenPublicKey(key *C.struct_RsaKey, e []byte, eSz *int, n []byte, nSz *int) int {
    if eSz == nil || nSz == nil {
        return BAD_FUNC_ARG
    }
    if *eSz < 0 || *eSz > len(e) || *nSz < 0 || *nSz > len(n) {
        return BAD_FUNC_ARG
    }
    if len(e) == 0 || len(n) == 0 {
        return BAD_FUNC_ARG
    }
    cESz := C.word32(*eSz)
    cNSz := C.word32(*nSz)
    ret := int(C.wc_RsaFlattenPublicKey(key,
        (*C.byte)(unsafe.Pointer(&e[0])), &cESz,
        (*C.byte)(unsafe.Pointer(&n[0])), &cNSz))
    *eSz = int(cESz)
    *nSz = int(cNSz)
    return ret
}
