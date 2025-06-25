/* curve25519.go
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

package wolfSSL

// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/curve25519.h>
// #include <wolfssl/wolfcrypt/random.h>
// #ifndef HAVE_CURVE25519
// typedef struct curve25519_key {} curve25519_key;
// #define EC25519_LITTLE_ENDIAN 1
// int wc_curve25519_init(curve25519_key* key) {
//     return -174;
// }
// void wc_curve25519_free(curve25519_key* key)  {
//     return;
// }
// int wc_curve25519_import_private(const byte* priv, word32 privSz, curve25519_key* key) {
//     return -174;
// }
// int wc_curve25519_import_public(const byte* in, word32 inLen, curve25519_key* key) {
//     return -174;
// }
// int wc_curve25519_export_private_raw(curve25519_key* key, byte* out, word32* outLen) {
//     return -174;
// }
// int wc_curve25519_make_key(WC_RNG* rng, int keysize, curve25519_key* key) {
//     return -174;
// }
// int wc_curve25519_make_priv(WC_RNG* rng, int keysize, byte* priv) {
//     return -174;
// }
// int wc_curve25519_make_pub(int public_size, byte* pub, int private_size, byte* priv) {
//     return -174;
// }
// int wc_curve25519_shared_secret_ex(curve25519_key* private_key,
//                                   curve25519_key* public_key,
//                                   byte* out, word32* outlen, int endian) {
//     return -174;
// }
// int wc_curve25519_import_private_ex(const byte* priv, word32 privSz,
//                                     curve25519_key* key, int endian) {
//      return -174;
// }
// int wc_curve25519_import_public_ex(const byte* in, word32 inLen,
//                                    curve25519_key* key, int endian) {
//      return -174;
// }
// #endif
import "C"
import (
    "unsafe"
)

type Curve25519_key = C.struct_curve25519_key

func Wc_curve25519_init(key *C.struct_curve25519_key) int {
    return int(C.wc_curve25519_init(key))
}

func Wc_curve25519_free(key *C.struct_curve25519_key) {
    C.wc_curve25519_free(key)
}

func Wc_curve25519_make_key(rng *C.struct_WC_RNG, keySize int, key *C.struct_curve25519_key) int {
    return int(C.wc_curve25519_make_key(rng, C.int(keySize), key))
}

func Wc_curve25519_make_pub(pub, priv []byte) int {
    return int(C.wc_curve25519_make_pub(C.int(len(pub)),(*C.uchar)(unsafe.Pointer(&pub[0])),
               C.int(len(priv)), (*C.uchar)(unsafe.Pointer(&priv[0]))))
}

func Wc_curve25519_make_priv(rng *C.struct_WC_RNG, priv []byte) int {
    return int(C.wc_curve25519_make_priv(rng,
               C.int(len(priv)), (*C.uchar)(unsafe.Pointer(&priv[0]))))
}

func Wc_curve25519_import_private(priv []byte, key *C.struct_curve25519_key) int {
    return int(C.wc_curve25519_import_private_ex((*C.uchar)(unsafe.Pointer(&priv[0])),
               C.word32(len(priv)), key, C.EC25519_LITTLE_ENDIAN))
}

func Wc_curve25519_import_public(pub []byte, key *C.struct_curve25519_key) int {
    return int(C.wc_curve25519_import_public_ex((*C.uchar)(unsafe.Pointer(&pub[0])),
               C.word32(len(pub)), key, C.EC25519_LITTLE_ENDIAN))
}

func Wc_curve25519_export_private_raw(key *C.struct_curve25519_key, priv []byte) int {
    outLen := len(priv)
    return int(C.wc_curve25519_export_private_raw(key, (*C.uchar)(unsafe.Pointer(&priv[0])), (*C.word32)(unsafe.Pointer(&outLen))))
}

func Wc_curve25519_shared_secret(privKey, pubKey *C.struct_curve25519_key, out []byte) int {
    outLen := len(out)
    return int(C.wc_curve25519_shared_secret_ex(privKey, pubKey, (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.word32)(unsafe.Pointer(&outLen)), C.EC25519_LITTLE_ENDIAN))
}
