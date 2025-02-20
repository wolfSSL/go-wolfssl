/* chacha_poly.go
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

package cgo

// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
// #ifndef HAVE_CHACHA
// #define CHACHA20_POLY1305_AEAD_KEYSIZE 1
// #define CHACHA20_POLY1305_AEAD_IV_SIZE 1
// #define CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE 1
// #define XCHACHA20_POLY1305_AEAD_NONCE_SIZE  1
// int wc_ChaCha20Poly1305_Encrypt(
//                 byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
//                 byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
//                 byte* inAAD, word32 inAADLen,
//                 byte* inPlaintext, word32 inPlaintextLen,
//                byte* outCiphertext,
//                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]) {
//      return -174;
// }
// int wc_ChaCha20Poly1305_Decrypt(
//                 byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
//                 byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
//                 byte* inAAD, word32 inAADLen,
//                 byte* inCiphertext, word32 inCiphertextLen,
//                 byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
//                byte* outPlaintext) {
//      return -174;
// }
// #endif
// #ifndef HAVE_XCHACHA
// int wc_XChaCha20Poly1305_Encrypt(
//    byte *dst, size_t dst_space,
//    const byte *src, size_t src_len,
//    const byte *ad, size_t ad_len,
//    const byte *nonce, size_t nonce_len,
//    const byte *key, size_t key_len) {
//      return -174;
// }
// int wc_XChaCha20Poly1305_Decrypt(
//    byte *dst, size_t dst_space,
//    const byte *src, size_t src_len,
//    const byte *ad, size_t ad_len,
//    const byte *nonce, size_t nonce_len,
//    const byte *key, size_t key_len) {
//      return -174;
// }
// #endif
import "C"
import (
    "unsafe"
)

const CHACHA20_POLY1305_AEAD_KEYSIZE = int(C.CHACHA20_POLY1305_AEAD_KEYSIZE)
const CHACHA20_POLY1305_AEAD_IV_SIZE = int(C.CHACHA20_POLY1305_AEAD_IV_SIZE)
const CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE = int(C.CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
const XCHACHA20_POLY1305_AEAD_NONCE_SIZE = int(C.XCHACHA20_POLY1305_AEAD_NONCE_SIZE)
const CHACHA20_POLY1305_AEAD_NONCE_SIZE = XCHACHA20_POLY1305_AEAD_NONCE_SIZE/2

func Wc_ChaCha20Poly1305_Encrypt(inKey, inIv, inAAD, inPlain, outCipher, outAuthTag []byte) int {
    var sanInAAD *C.uchar
    if len(inAAD) > 0 {
        sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
    } else {
        sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanInPlain *C.uchar
    if len(inPlain) > 0 {
        sanInPlain = (*C.uchar)(unsafe.Pointer(&inPlain[0]))
    } else {
        sanInPlain = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanOutCipher *C.uchar
    if len(outCipher) > 0 {
        sanOutCipher = (*C.uchar)(unsafe.Pointer(&outCipher[0]))
    } else {
        emptyStringArray := []byte("")
        sanOutCipher = (*C.uchar)(unsafe.Pointer(&emptyStringArray))
    }
    return int(C.wc_ChaCha20Poly1305_Encrypt((*C.uchar)(unsafe.Pointer(&inKey[0])), (*C.uchar)(unsafe.Pointer(&inIv[0])),
               sanInAAD, C.word32(len(inAAD)), sanInPlain, C.word32(len(inPlain)),
               sanOutCipher, (*C.uchar)(unsafe.Pointer(&outAuthTag[0]))))
}

func Wc_ChaCha20Poly1305_Decrypt(inKey, inIv, inAAD, inCipher, inAuthTag , outPlain []byte) int {
    var sanInAAD *C.uchar
    if len(inAAD) > 0 {
        sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
    } else {
        sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanInCipher *C.uchar
    if len(inCipher) > 0 {
        sanInCipher = (*C.uchar)(unsafe.Pointer(&inCipher[0]))
    } else {
        emptyStringArray := []byte("")
        sanInCipher = (*C.uchar)(unsafe.Pointer(&emptyStringArray))
    }

    return int(C.wc_ChaCha20Poly1305_Decrypt((*C.uchar)(unsafe.Pointer(&inKey[0])), (*C.uchar)(unsafe.Pointer(&inIv[0])),
               sanInAAD, C.word32(len(inAAD)), sanInCipher, C.word32(len(inCipher)),
               (*C.uchar)(unsafe.Pointer(&inAuthTag[0])), (*C.uchar)(unsafe.Pointer(&outPlain[0]))))
}

func Wc_ChaCha20Poly1305_Appended_Tag_Encrypt(inKey, inIv, inAAD, inPlain, outCipher []byte) ([]byte, int) {
    var outAuthTag [CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]byte
    var longOutCipher []byte

    if len(outCipher) < (len(inPlain) + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        longOutCipher = make([]byte, len(inPlain) + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
    } else {
        longOutCipher = outCipher
    }

    ret := Wc_ChaCha20Poly1305_Encrypt(inKey, inIv, inAAD, inPlain, longOutCipher[:(len(longOutCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)], outAuthTag[:])
    copy(longOutCipher[(len(longOutCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE):], outAuthTag[:])
    return longOutCipher, ret
}

func Wc_ChaCha20Poly1305_Appended_Tag_Decrypt(inKey, inIv, inAAD, inCipher,  outPlain []byte) int {
    var inAuthTag [CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]byte
    copy(inAuthTag[:], inCipher[(len(inCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE):])
    ret := Wc_ChaCha20Poly1305_Decrypt(inKey, inIv, inAAD, inCipher[:(len(inCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)], inAuthTag[:] , outPlain)
    return ret
}

func Wc_XChaCha20Poly1305_Encrypt(outCipher, inPlain, inAAD, inIv, inKey []byte) int {
    var sanInAAD *C.uchar
    if len(inAAD) > 0 {
        sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
    } else {
        sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanInPlain *C.uchar
    if len(inPlain) > 0 {
        sanInPlain = (*C.uchar)(unsafe.Pointer(&inPlain[0]))
    } else {
        sanInPlain = (*C.uchar)(unsafe.Pointer(nil))
    }
    return int(C.wc_XChaCha20Poly1305_Encrypt((*C.uchar)(unsafe.Pointer(&outCipher[0])), C.size_t(len(outCipher)),
                sanInPlain, C.size_t(len(inPlain)), sanInAAD, C.size_t(len(inAAD)),
                (*C.uchar)(unsafe.Pointer(&inIv[0])), C.size_t(len(inIv)),
                (*C.uchar)(unsafe.Pointer(&inKey[0])), C.size_t(len(inKey))))
}

func Wc_XChaCha20Poly1305_Decrypt(outPlain, inCipher, inAAD, inIv, inKey []byte) int {
    var sanInAAD *C.uchar
    if len(inAAD) > 0 {
        sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
    } else {
        sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanInCipher *C.uchar
    if len(inCipher) > 0 {
        sanInCipher = (*C.uchar)(unsafe.Pointer(&inCipher[0]))
    } else {
        sanInCipher = (*C.uchar)(unsafe.Pointer(nil))
    }
    return int(C.wc_XChaCha20Poly1305_Decrypt((*C.uchar)(unsafe.Pointer(&outPlain[0])), C.size_t(len(outPlain)),
                sanInCipher, C.size_t(len(inCipher)), sanInAAD, C.size_t(len(inAAD)),
                (*C.uchar)(unsafe.Pointer(&inIv[0])), C.size_t(len(inIv)),
                (*C.uchar)(unsafe.Pointer(&inKey[0])), C.size_t(len(inKey))))
}
