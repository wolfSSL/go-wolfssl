/* ecc.go
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

package ecc

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
)

type Key = cgo.Ecc_key

const (
    ECC_MAX_SIG_SIZE = cgo.ECC_MAX_SIG_SIZE
    ECC_SECP256R1 = cgo.ECC_SECP256R1
)

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
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_ecc_export_private_only(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    return ret
}

func Wc_ecc_export_x963_ex(key *C.struct_ecc_key, out []byte, outLen *int, compressed int) int {
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_ecc_export_x963_ex(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen, C.int(compressed)))
    *outLen = int(cOutLen)
    return ret
}

func Wc_ecc_import_private_key_ex(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_ecc_key, curveId int) int {
    privPtr := (*C.byte)(unsafe.Pointer(&priv[0]))
    var pubPtr *C.byte

    if pubSz > 0 {
        pubPtr = (*C.byte)(unsafe.Pointer(&pub[0]))
    }

    return int(C.wc_ecc_import_private_key_ex(privPtr, C.word32(privSz), pubPtr, C.word32(pubSz), key, C.int(curveId)))
}

func Wc_ecc_import_x963_ex(pubKey []byte, pubSz int, key *C.struct_ecc_key, curveID int) int {
	return int(C.wc_ecc_import_x963_ex((*C.uchar)(unsafe.Pointer(&pubKey[0])), C.word32(pubSz), key, C.int(curveID)))
}

func Wc_ecc_sign_hash(in []byte, inLen int, out []byte, outLen *int, rng *C.struct_WC_RNG, key *C.struct_ecc_key) int {
    return int(C.wc_ecc_sign_hash((*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
               (*C.uchar)(unsafe.Pointer(&out[0])), (*C.word32)(unsafe.Pointer(outLen)), rng, key))
}

func Wc_ecc_verify_hash(sig []byte, sigLen int, hash []byte, hashLen int, res *int, key *C.struct_ecc_key) int {
    return int(C.wc_ecc_verify_hash((*C.uchar)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
               (*C.uchar)(unsafe.Pointer(&hash[0])), C.word32(sigLen), (*C.int)(unsafe.Pointer(res)), key))
}

func Wc_ecc_shared_secret(privKey, pubKey *C.struct_ecc_key, out []byte, outLen *int) int {
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_ecc_shared_secret(privKey, pubKey, (*C.uchar)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    return ret
}
