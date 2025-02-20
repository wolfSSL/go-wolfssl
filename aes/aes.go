/* aes.go
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

package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/pwdbased.h>
// #ifdef NO_AES
// #define AES_BLOCK_SIZE   1
// #define AES_128_KEY_SIZE 1
// #define AES_192_KEY_SIZE 1
// #define AES_256_KEY_SIZE 1
// #define AES_ENCRYPTION   1
// #define AES_DECRYPTION   1
// typedef struct Aes {} Aes;
// int wc_AesInit(Aes* aes, void* heap, int devid) {
//      return -174;
//  }
// int wc_AesFree(Aes* aes) {
//      return -174;
//  }
// int wc_AesSetKey(Aes* aes, const byte* key, word32 len,
//                 const byte* iv, int dir) {
//      return -174;
// }
// #ifndef HAVE_AES_CBC
// int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// #endif
// #endif
import "C"
import (
    "unsafe"
)

const AES_IV_SIZE      = int(C.AES_IV_SIZE)
const AES_BLOCK_SIZE   = int(C.AES_BLOCK_SIZE)
const AES_128_KEY_SIZE = int(C.AES_128_KEY_SIZE)
const AES_192_KEY_SIZE = int(C.AES_192_KEY_SIZE)
const AES_256_KEY_SIZE = int(C.AES_256_KEY_SIZE)
const AES_ENCRYPTION   = int(C.AES_ENCRYPTION)
const AES_DECRYPTION   = int(C.AES_DECRYPTION)

const INVALID_DEVID    = int(C.INVALID_DEVID)

type Aes = C.struct_Aes

func Wc_AesInit(aes *C.struct_Aes, heap []byte , devId int) int {
        /* TODO: HANDLE NON NIL HEAP */
    return int(C.wc_AesInit(aes, unsafe.Pointer(nil), C.int(devId)))
}

func Wc_AesFree(aes *C.struct_Aes) {
    C.wc_AesFree(aes)
}

func Wc_AesSetKey(aes *C.struct_Aes, key []byte, length int, iv []byte, dir int) int {
    return int(C.wc_AesSetKey(aes, (*C.uchar)(unsafe.Pointer(&key[0])), C.word32(length),
               (*C.uchar)(unsafe.Pointer(&iv[0])), C.int(dir)))
}

func Wc_AesCbcEncrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    return int(C.wc_AesCbcEncrypt(aes, (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])), C.word32(sz)))
}

func Wc_AesCbcDecrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    return int(C.wc_AesCbcDecrypt(aes, (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])), C.word32(sz)))
}

func Wc_AesGcmSetKey(aes *C.struct_Aes, key []byte, length int) int {
    return int(C.wc_AesGcmSetKey(aes, (*C.uchar)(unsafe.Pointer(&key[0])), C.word32(length)))
}

func Wc_AesGcmEncrypt(aes *C.struct_Aes, outCipher, inPlain, inIv, outAuthTag, inAAD []byte) int {
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
        emptyStringArray := []byte("")
        sanInPlain = (*C.uchar)(unsafe.Pointer(&emptyStringArray))
    }
    var sanOutCipher *C.uchar
    if len(outCipher) > 0 {
        sanOutCipher = (*C.uchar)(unsafe.Pointer(&outCipher[0]))
    } else {
        outCipher = make([]byte, AES_BLOCK_SIZE)
        sanOutCipher = (*C.uchar)(unsafe.Pointer(&outCipher[0]))
    }
    ret := int(C.wc_AesGcmEncrypt(aes, sanOutCipher, sanInPlain, C.word32(len(inPlain)),
               (*C.uchar)(unsafe.Pointer(&inIv[0])), C.word32(len(inIv)),
               (*C.uchar)(unsafe.Pointer(&outAuthTag[0])), C.word32(len(outAuthTag)), sanInAAD, C.word32(len(inAAD))))
    return ret
}

func Wc_AesGcmDecrypt(aes *C.struct_Aes, outPlain, inCipher, inIv, inAuthTag, inAAD []byte) int {
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

    ret := int(C.wc_AesGcmDecrypt(aes, (*C.uchar)(unsafe.Pointer(&outPlain[0])), sanInCipher, C.word32(len(inCipher)),
               (*C.uchar)(unsafe.Pointer(&inIv[0])), C.word32(len(inIv)),
               (*C.uchar)(unsafe.Pointer(&inAuthTag[0])), C.word32(len(inAuthTag)), sanInAAD, C.word32(len(inAAD))))
    return ret

}

func Wc_AesGcm_Appended_Tag_Encrypt(aes *C.struct_Aes, outCipher, inPlain, inIv, inAAD []byte) ([]byte, int) {
    var outAuthTag [AES_BLOCK_SIZE]byte
    var longOutCipher []byte

    if len(outCipher) < (len(inPlain) + AES_BLOCK_SIZE) {
        longOutCipher = make([]byte, len(inPlain) + AES_BLOCK_SIZE)
    } else {
        longOutCipher = outCipher
    }

    ret := Wc_AesGcmEncrypt(aes, longOutCipher[:(len(longOutCipher)-AES_BLOCK_SIZE)], inPlain, inIv, outAuthTag[:], inAAD)
    copy(longOutCipher[(len(longOutCipher)-AES_BLOCK_SIZE):], outAuthTag[:])
    return longOutCipher, ret
}

func Wc_AesGcm_Appended_Tag_Decrypt(aes *C.struct_Aes, outPlain, inCipher, inIv, inAAD []byte) int {
    var inAuthTag [AES_BLOCK_SIZE]byte
    copy(inAuthTag[:], inCipher[(len(inCipher)-AES_BLOCK_SIZE):])
    ret := Wc_AesGcmDecrypt(aes, outPlain, inCipher[:(len(inCipher)-AES_BLOCK_SIZE)], inIv, inAuthTag[:], inAAD)
    return ret
}

/* TODO: Move function below to appropriate .go file */
func Wc_PBKDF2(out []byte, pwd []byte, pLen int, salt []byte, saltLen int, iter int, kLen int, typeH int) int {
    return int(C.wc_PBKDF2((*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&pwd[0])), C.int(pLen),
               (*C.uchar)(unsafe.Pointer(&salt[0])), C.int(saltLen), C.int(iter), C.int(kLen), C.int(typeH)))
}

