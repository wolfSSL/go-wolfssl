/* ecc.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/random.h>
// #ifndef HAVE_ECC
// #define ECC_MAX_SIG_SIZE 1
// #define ECC_SECP256R1 1
// typedef struct ecc_key {} ecc_key;
// typedef struct ecc_point {} ecc_point;
// int wc_ecc_init(ecc_key *key) {
//      return -174;
//  }
// int wc_ecc_free(ecc_key *key) {
//      return -174;
//  }
// int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key) {
//      return -174;
//  }
// int wc_ecc_make_pub(ecc_key* key, ecc_point* pubOut) {
//      return -174;
//  }
// int wc_ecc_set_rng(ecc_key* key, WC_RNG* rng) {
//      return -174;
//  }
// int wc_ecc_export_private_only(ecc_key* key, byte* out, word32* outLen) {
//      return -174;
//  }
// int wc_ecc_export_x963_ex(ecc_key* key, byte* out, word32* outLen,
//                           int compressed) {
//      return -174;
//  }
// int wc_ecc_import_private_key_ex(const byte* priv, word32 privSz,
//                                  const byte* pub, word32 pubSz,
//                                  ecc_key* key, int curve_id) {
//      return -174;
//  }
// int wc_ecc_import_x963_ex(const byte* in, word32 inLen, ecc_key* key,
//                           int curve_id) {
//      return -174;
//  }
// int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
//                      WC_RNG* rng, ecc_key* key) {
//      return -174;
//  }
// int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
//                        word32 hashlen, int* res, ecc_key* key) {
//      return -174;
//  }
// int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
//                        ecc_key* key, word32 inSz) {
//      return -174;
//  }
// int wc_ecc_check_key(ecc_key* key) {
//      return -174;
//  }
// int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
//                          byte* out, word32* outlen) {
//      return -174;
//  }
// int wc_ecc_export_public_raw(ecc_key* key, byte* qx, word32* qxLen,
//                              byte* qy, word32* qyLen) {
//      return -174;
//  }
// int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx,
//                            ecc_key* key, word32 inSz) {
//      return -174;
//  }
// int wc_EccKeyToDer(ecc_key* key, byte* output, word32 inLen) {
//      return -174;
//  }
// int wc_EccPrivateKeyToDer(ecc_key* key, byte* output, word32 inLen) {
//      return -174;
//  }
// int wc_EccKeyToPKCS8(ecc_key* key, byte* output, word32* outLen) {
//      return -174;
//  }
// int wc_EccPublicKeyToDer(ecc_key* key, byte* output, word32 inLen,
//                          int with_AlgCurve) {
//      return -174;
//  }
// #endif
//
// /* Negate an ECC private key: d' = order - d, then regenerate the public key */
// #if defined(HAVE_ECC) && defined(WOLFSSL_PUBLIC_MP)
// static int wc_ecc_negate_private(ecc_key* key) {
//     mp_int order;
//     int ret;
//     mp_int* priv;
// #ifdef WOLFSSL_HAVE_ECC_KEY_GET_PRIV
//     priv = wc_ecc_key_get_priv(key);
// #else
//     priv = &key->k;
// #endif
//     ret = mp_init(&order);
//     if (ret != 0) return ret;
//     ret = mp_read_radix(&order, key->dp->order, MP_RADIX_HEX);
//     if (ret == 0)
//         ret = mp_sub(&order, priv, priv);
//     mp_clear(&order);
//     if (ret == 0)
//         ret = wc_ecc_make_pub(key, NULL);
//     return ret;
// }
// #else
// static int wc_ecc_negate_private(ecc_key* key) {
//     (void)key; return -174;
// }
// #endif
import "C"
import (
    "unsafe"
)

const ECC_MAX_SIG_SIZE = int(C.ECC_MAX_SIG_SIZE)

type Ecc_key = C.struct_ecc_key

const ECC_SECP256R1 = int(C.ECC_SECP256R1)

func Wc_ecc_init(key *C.struct_ecc_key) int {
    return int(C.wc_ecc_init(key))
}

func Wc_ecc_free(key *C.struct_ecc_key) int {
    return int(C.wc_ecc_free(key))
}

func Wc_ecc_make_key(rng *C.struct_WC_RNG, keySize int, key *C.struct_ecc_key) int {
    return int(C.wc_ecc_make_key(rng, C.int(keySize), key))
}

func Wc_ecc_make_pub_in_priv(key *C.struct_ecc_key) int {
    return int(C.wc_ecc_make_pub(key, nil))
}

func Wc_ecc_set_rng(key *C.struct_ecc_key, rng *C.struct_WC_RNG) int {
    return int(C.wc_ecc_set_rng(key, rng))
}

func Wc_ecc_export_private_only(key *C.struct_ecc_key, out []byte, outLen *int) int {
    if outLen == nil || len(out) == 0 || *outLen < 0 || *outLen > len(out) {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    PRIVATE_KEY_UNLOCK()
    ret := int(C.wc_ecc_export_private_only(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    PRIVATE_KEY_LOCK()
    return ret
}

func Wc_ecc_export_x963_ex(key *C.struct_ecc_key, out []byte, outLen *int, compressed int) int {
    if outLen == nil || len(out) == 0 || *outLen < 0 || *outLen > len(out) {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    PRIVATE_KEY_UNLOCK()
    ret := int(C.wc_ecc_export_x963_ex(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen, C.int(compressed)))
    *outLen = int(cOutLen)
    PRIVATE_KEY_LOCK()
    return ret
}

func Wc_ecc_import_private_key_ex(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_ecc_key, curveId int) int {
    if privSz < 0 || privSz > len(priv) {
        return BAD_FUNC_ARG
    }
    if pubSz < 0 || pubSz > len(pub) {
        return BAD_FUNC_ARG
    }
    if len(priv) == 0 {
        return BAD_FUNC_ARG
    }
    privPtr := (*C.byte)(unsafe.Pointer(&priv[0]))
    var pubPtr *C.byte

    if pubSz > 0 {
        pubPtr = (*C.byte)(unsafe.Pointer(&pub[0]))
    }

    return int(C.wc_ecc_import_private_key_ex(privPtr, C.word32(privSz), pubPtr, C.word32(pubSz), key, C.int(curveId)))
}

func Wc_ecc_import_x963_ex(pubKey []byte, pubSz int, key *C.struct_ecc_key, curveID int) int {
    if pubSz < 0 || pubSz > len(pubKey) {
        return BAD_FUNC_ARG
    }
    if len(pubKey) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_ecc_import_x963_ex((*C.uchar)(unsafe.Pointer(&pubKey[0])), C.word32(pubSz), key, C.int(curveID)))
}

func Wc_ecc_sign_hash(in []byte, inLen int, out []byte, outLen *int, rng *C.struct_WC_RNG, key *C.struct_ecc_key) int {
    if inLen < 0 || inLen > len(in) {
        return BAD_FUNC_ARG
    }
    if outLen == nil || len(in) == 0 || len(out) == 0 || *outLen < 0 || *outLen > len(out) {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_ecc_sign_hash((*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
        (*C.uchar)(unsafe.Pointer(&out[0])), &cOutLen, rng, key))
    *outLen = int(cOutLen)
    return ret
}

func Wc_ecc_verify_hash(sig []byte, sigLen int, hash []byte, hashLen int, res *int, key *C.struct_ecc_key) int {
    if sigLen < 0 || sigLen > len(sig) {
        return BAD_FUNC_ARG
    }
    if hashLen < 0 || hashLen > len(hash) {
        return BAD_FUNC_ARG
    }
    if res == nil || len(sig) == 0 || len(hash) == 0 {
        return BAD_FUNC_ARG
    }
    cRes := C.int(*res)
    ret := int(C.wc_ecc_verify_hash((*C.uchar)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
        (*C.uchar)(unsafe.Pointer(&hash[0])), C.word32(hashLen), &cRes, key))
    *res = int(cRes)
    return ret
}

func Wc_ecc_check_key(key *C.struct_ecc_key) int {
    return int(C.wc_ecc_check_key(key))
}

func Wc_ecc_shared_secret(privKey, pubKey *C.struct_ecc_key, out []byte, outLen *int) int {
    if outLen == nil || len(out) == 0 || *outLen < 0 || *outLen > len(out) {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    PRIVATE_KEY_UNLOCK()
    ret := int(C.wc_ecc_shared_secret(privKey, pubKey, (*C.uchar)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    PRIVATE_KEY_LOCK()
    return ret
}

func Wc_EccPublicKeyDecode(pubKey []byte, idx *int, key *C.struct_ecc_key, pubSz int) int {
    if pubSz < 0 || pubSz > len(pubKey) {
        return BAD_FUNC_ARG
    }
    if idx == nil || len(pubKey) == 0 || *idx < 0 || *idx > pubSz {
        return BAD_FUNC_ARG
    }
    cIdx := C.word32(*idx)
    ret := int(C.wc_EccPublicKeyDecode((*C.uchar)(unsafe.Pointer(&pubKey[0])), &cIdx, key, C.word32(pubSz)))
    *idx = int(cIdx)
    return ret
}

func Wc_ecc_negate_private(key *C.struct_ecc_key) int {
    return int(C.wc_ecc_negate_private(key))
}

func Wc_ecc_export_public_raw(key *C.struct_ecc_key, qx []byte, qxLen *int, qy []byte, qyLen *int) int {
    if qxLen == nil || qyLen == nil || len(qx) == 0 || len(qy) == 0 {
        return BAD_FUNC_ARG
    }
    if *qxLen < 0 || *qxLen > len(qx) || *qyLen < 0 || *qyLen > len(qy) {
        return BAD_FUNC_ARG
    }
    cQxLen := C.word32(*qxLen)
    cQyLen := C.word32(*qyLen)
    ret := int(C.wc_ecc_export_public_raw(key,
        (*C.byte)(unsafe.Pointer(&qx[0])), &cQxLen,
        (*C.byte)(unsafe.Pointer(&qy[0])), &cQyLen))
    *qxLen = int(cQxLen)
    *qyLen = int(cQyLen)
    return ret
}

func Wc_EccPrivateKeyDecode(input []byte, idx *int, key *C.struct_ecc_key, inSz int) int {
    if inSz < 0 || inSz > len(input) || idx == nil || *idx < 0 || *idx > inSz || len(input) == 0 {
        return BAD_FUNC_ARG
    }
    cIdx := C.word32(*idx)
    ret := int(C.wc_EccPrivateKeyDecode((*C.byte)(unsafe.Pointer(&input[0])), &cIdx, key, C.word32(inSz)))
    *idx = int(cIdx)
    return ret
}

func Wc_EccKeyToDer(key *C.struct_ecc_key, out []byte) int {
    if len(out) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_EccKeyToDer(key, (*C.byte)(unsafe.Pointer(&out[0])), C.word32(len(out))))
}


func Wc_EccPrivateKeyToDer(key *C.struct_ecc_key, out []byte) int {
    var outPtr *C.byte
    if len(out) > 0 {
        outPtr = (*C.byte)(unsafe.Pointer(&out[0]))
    }
    return int(C.wc_EccPrivateKeyToDer(key, outPtr, C.word32(len(out))))
}

func Wc_EccKeyToPKCS8(key *C.struct_ecc_key, out []byte, outLen *int) int {
    if outLen == nil || *outLen < 0 || *outLen > len(out) {
        return BAD_FUNC_ARG
    }
    var outPtr *C.byte
    if len(out) > 0 {
        outPtr = (*C.byte)(unsafe.Pointer(&out[0]))
    }
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_EccKeyToPKCS8(key, outPtr, &cOutLen))
    *outLen = int(cOutLen)
    return ret
}

func Wc_EccPublicKeyToDer(key *C.struct_ecc_key, out []byte, withAlgCurve int) int {
    var outPtr *C.byte
    if len(out) > 0 {
        outPtr = (*C.byte)(unsafe.Pointer(&out[0]))
    }
    return int(C.wc_EccPublicKeyToDer(key, outPtr, C.word32(len(out)), C.int(withAlgCurve)))
}

func Wc_GetPkcs8TraditionalOffset(input []byte, idx *int) int {
    if idx == nil || *idx < 0 || *idx > len(input) || len(input) == 0 {
        return BAD_FUNC_ARG
    }
    cIdx := C.word32(*idx)
    ret := int(C.wc_GetPkcs8TraditionalOffset((*C.byte)(unsafe.Pointer(&input[0])), &cIdx, C.word32(len(input))))
    *idx = int(cIdx)
    return ret
}

func Wc_KeyPemToDer(pem []byte, out []byte, pass string) int {
    if len(pem) == 0 {
        return BAD_FUNC_ARG
    }
    cPass := C.CString(pass)
    defer C.free(unsafe.Pointer(cPass))
    var outPtr *C.uchar
    if len(out) > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    return int(C.wc_KeyPemToDer((*C.uchar)(unsafe.Pointer(&pem[0])), C.int(len(pem)),
        outPtr, C.int(len(out)), cPass))
}
