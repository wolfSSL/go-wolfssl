/* aes.go
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

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/pwdbased.h>
// #ifdef NO_AES
// #define AES_BLOCK_SIZE   1
// #define AES_IV_SIZE      1
// #define AES_128_KEY_SIZE 1
// #define AES_192_KEY_SIZE 1
// #define AES_256_KEY_SIZE 1
// #define AES_ENCRYPTION   1
// #define AES_DECRYPTION   1
// typedef struct Aes {} Aes;
// int wc_AesInit(Aes* aes, void* heap, int devid) {
//      return -174;
// }
// void wc_AesFree(Aes* aes) {
//      return;
// }
// int wc_AesSetKey(Aes* aes, const byte* key, word32 len,
//                 const byte* iv, int dir) {
//      return -174;
// }
// int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len) {
//      return -174;
// }
// int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
//                      const byte* iv, word32 ivSz,
//                      byte* authTag, word32 authTagSz,
//                      const byte* authIn, word32 authInSz) {
//      return -174;
// }
// int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
//                      const byte* iv, word32 ivSz,
//                      const byte* authTag, word32 authTagSz,
//                      const byte* authIn, word32 authInSz) {
//      return -174;
// }
// Aes* wc_AesAllocAligned(void) { return NULL; }
// void wc_AesFreeAllocAligned(Aes* ptr) { (void)ptr; }
// #elif defined(_WIN32)
// #include <stdlib.h>
// #include <malloc.h>
// Aes* wc_AesAllocAligned(void) {
//     Aes* ptr = (Aes*)_aligned_malloc(sizeof(Aes),16);
//     return ptr;
// }
// void wc_AesFreeAllocAligned(Aes* ptr) {
//     _aligned_free(ptr);
// }
// #else
// #include <stdlib.h>
// Aes* wc_AesAllocAligned(void) {
//     Aes* ptr;
//     if (posix_memalign((void**)&ptr, 16, sizeof(Aes)) != 0) {
//         return NULL;
//     }
//     return ptr;
// }
// void wc_AesFreeAllocAligned(Aes* ptr) {
//     free(ptr);
// }
// #endif
// #if !defined(NO_AES) && !defined(HAVE_AES_CBC)
// int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// #endif
// #if !defined(NO_AES) && !defined(HAVE_AESGCM)
// int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len) {
//      return -174;
// }
// int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
//                      const byte* iv, word32 ivSz,
//                      byte* authTag, word32 authTagSz,
//                      const byte* authIn, word32 authInSz) {
//      return -174;
// }
// int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
//                      const byte* iv, word32 ivSz,
//                      const byte* authTag, word32 authTagSz,
//                      const byte* authIn, word32 authInSz) {
//      return -174;
// }
// #endif
// #ifdef NO_PWDBASED
// int wc_PBKDF2(byte* output, const byte* passwd, int pLen,
//               const byte* salt, int sLen, int iterations,
//               int kLen, int typeH) {
//      (void)output; (void)passwd; (void)pLen;
//      (void)salt; (void)sLen; (void)iterations;
//      (void)kLen; (void)typeH;
//      return -174;
// }
// #endif
import "C"
import (
    "math"
    "unsafe"
)

const AES_IV_SIZE      = int(C.AES_IV_SIZE)
const AES_BLOCK_SIZE   = int(C.AES_BLOCK_SIZE)
const GCM_NONCE_MID_SZ = int(C.GCM_NONCE_MID_SZ)
const AES_128_KEY_SIZE = int(C.AES_128_KEY_SIZE)
const AES_192_KEY_SIZE = int(C.AES_192_KEY_SIZE)
const AES_256_KEY_SIZE = int(C.AES_256_KEY_SIZE)
const AES_ENCRYPTION   = int(C.AES_ENCRYPTION)
const AES_DECRYPTION   = int(C.AES_DECRYPTION)

const INVALID_DEVID    = int(C.INVALID_DEVID)

type Aes = C.struct_Aes

/* Returns a 16-byte aligned Aes Struct allocated on the C Heap (needed by AES-NI) */
func Wc_AesAllocAligned() *C.struct_Aes {
    return C.wc_AesAllocAligned()
}

func Wc_AesFreeAllocAligned(aes *C.struct_Aes) {
    C.wc_AesFreeAllocAligned(aes)
}

func Wc_AesInit(aes *C.struct_Aes, heap []byte , devId int) int {
        /* TODO: HANDLE NON NIL HEAP */
    return int(C.wc_AesInit(aes, unsafe.Pointer(nil), C.int(devId)))
}

func Wc_AesFree(aes *C.struct_Aes) {
    C.wc_AesFree(aes)
}

func Wc_AesSetKey(aes *C.struct_Aes, key []byte, length int, iv []byte, dir int) int {
    if length < 0 || length > len(key) { return BAD_FUNC_ARG }
    if len(key) == 0 { return BAD_FUNC_ARG }
    var ivPtr *C.uchar
    if len(iv) > 0 {
        ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
    }
    return int(C.wc_AesSetKey(aes, (*C.uchar)(unsafe.Pointer(&key[0])), C.word32(length),
               ivPtr, C.int(dir)))
}

func Wc_AesCbcEncrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_AesCbcEncrypt(aes, (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])), C.word32(sz)))
}

func Wc_AesCbcDecrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_AesCbcDecrypt(aes, (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])), C.word32(sz)))
}

func Wc_AesGcmSetKey(aes *C.struct_Aes, key []byte, length int) int {
    if length < 0 || length > len(key) { return BAD_FUNC_ARG }
    if len(key) == 0 { return BAD_FUNC_ARG }
    return int(C.wc_AesGcmSetKey(aes, (*C.uchar)(unsafe.Pointer(&key[0])), C.word32(length)))
}

func Wc_AesGcmEncrypt(aes *C.struct_Aes, outCipher, inPlain, inIv, outAuthTag, inAAD []byte) int {
    if len(inIv) == 0 || len(outAuthTag) == 0 { return BAD_FUNC_ARG }
    if len(outCipher) < len(inPlain) { return BAD_FUNC_ARG }
    var sanInAAD *C.uchar
    if len(inAAD) > 0 {
        sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
    } else {
        sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanInPlain *C.uchar
    if len(inPlain) > 0 {
        sanInPlain = (*C.uchar)(unsafe.Pointer(&inPlain[0]))
    }
    var sanOutCipher *C.uchar
    if len(outCipher) > 0 {
        sanOutCipher = (*C.uchar)(unsafe.Pointer(&outCipher[0]))
    }
    ret := int(C.wc_AesGcmEncrypt(aes, sanOutCipher, sanInPlain, C.word32(len(inPlain)),
               (*C.uchar)(unsafe.Pointer(&inIv[0])), C.word32(len(inIv)),
               (*C.uchar)(unsafe.Pointer(&outAuthTag[0])), C.word32(len(outAuthTag)), sanInAAD, C.word32(len(inAAD))))
    return ret
}

func Wc_AesGcmDecrypt(aes *C.struct_Aes, outPlain, inCipher, inIv, inAuthTag, inAAD []byte) int {
    if len(inIv) == 0 || len(inAuthTag) == 0 { return BAD_FUNC_ARG }
    if len(outPlain) < len(inCipher) { return BAD_FUNC_ARG }
    var sanInAAD *C.uchar
    if len(inAAD) > 0 {
        sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
    } else {
        sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanInCipher *C.uchar
    if len(inCipher) > 0 {
        sanInCipher = (*C.uchar)(unsafe.Pointer(&inCipher[0]))
    }

    var sanOutPlain *C.uchar
    if len(outPlain) > 0 {
        sanOutPlain = (*C.uchar)(unsafe.Pointer(&outPlain[0]))
    }

    ret := int(C.wc_AesGcmDecrypt(aes, sanOutPlain, sanInCipher, C.word32(len(inCipher)),
               (*C.uchar)(unsafe.Pointer(&inIv[0])), C.word32(len(inIv)),
               (*C.uchar)(unsafe.Pointer(&inAuthTag[0])), C.word32(len(inAuthTag)), sanInAAD, C.word32(len(inAAD))))
    return ret

}

// Wc_AesGcm_Appended_Tag_Encrypt encrypts inPlain and appends the GCM tag,
// returning a slice of length exactly len(inPlain)+AES_BLOCK_SIZE. If
// outCipher is large enough it is used as backing storage; otherwise a new
// slice is allocated.
func Wc_AesGcm_Appended_Tag_Encrypt(aes *C.struct_Aes, outCipher, inPlain, inIv, inAAD []byte) ([]byte, int) {
    var outAuthTag [AES_BLOCK_SIZE]byte
    var longOutCipher []byte

    need := len(inPlain) + AES_BLOCK_SIZE
    if len(outCipher) < need {
        longOutCipher = make([]byte, need)
    } else {
        // Reslice to `need` so the returned cipher||tag has no gap when
        // outCipher is oversized; reverting this re-introduces uninitialized
        // bytes between ciphertext and tag.
        longOutCipher = outCipher[:need]
    }

    ret := Wc_AesGcmEncrypt(aes, longOutCipher[:len(inPlain)], inPlain, inIv, outAuthTag[:], inAAD)
    copy(longOutCipher[len(inPlain):], outAuthTag[:])
    return longOutCipher, ret
}

func Wc_AesGcm_Appended_Tag_Decrypt(aes *C.struct_Aes, outPlain, inCipher, inIv, inAAD []byte) int {
    if len(inCipher) < AES_BLOCK_SIZE {
        return BAD_FUNC_ARG
    }
    var inAuthTag [AES_BLOCK_SIZE]byte
    copy(inAuthTag[:], inCipher[(len(inCipher)-AES_BLOCK_SIZE):])
    ret := Wc_AesGcmDecrypt(aes, outPlain, inCipher[:(len(inCipher)-AES_BLOCK_SIZE)], inIv, inAuthTag[:], inAAD)
    return ret
}

/* TODO: Move function below to appropriate .go file */
func Wc_PBKDF2(out []byte, pwd []byte, pLen int, salt []byte, saltLen int, iter int, kLen int, typeH int) int {
    if pLen < 0 || saltLen < 0 || kLen < 0 ||
       pLen > len(pwd) || saltLen > len(salt) || kLen > len(out) {
        return BAD_FUNC_ARG
    }
    if iter <= 0 || iter > math.MaxInt32 {
        return BAD_FUNC_ARG
    }
    if pLen > math.MaxInt32 || saltLen > math.MaxInt32 || kLen > math.MaxInt32 {
        return BAD_FUNC_ARG
    }
    var outPtr *C.uchar
    if len(out) > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    var pwdPtr *C.uchar
    if len(pwd) > 0 {
        pwdPtr = (*C.uchar)(unsafe.Pointer(&pwd[0]))
    }
    var saltPtr *C.uchar
    if len(salt) > 0 {
        saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
    }
    return int(C.wc_PBKDF2(outPtr, pwdPtr, C.int(pLen),
               saltPtr, C.int(saltLen), C.int(iter), C.int(kLen), C.int(typeH)))
}

