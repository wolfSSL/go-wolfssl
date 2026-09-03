/* hmac.go
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

// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/hmac.h>
// #ifdef _WIN32
// #include <stdlib.h>
// #include <malloc.h>
// Hmac* wc_HmacAllocAligned(void) {
//     Hmac* ptr = (Hmac*)_aligned_malloc(sizeof(Hmac), 16);
//     return ptr;
// }
// void wc_HmacFreeAllocAligned(Hmac* ptr) {
//     _aligned_free(ptr);
// }
// #else
// #include <stdlib.h>
// Hmac* wc_HmacAllocAligned(void) {
//     Hmac* ptr;
//     if (posix_memalign((void**)&ptr, 16, sizeof(Hmac)) != 0) {
//         return NULL;
//     }
//     return ptr;
// }
// void wc_HmacFreeAllocAligned(Hmac* ptr) {
//     free(ptr);
// }
// #endif
// /* unlock/op/lock must stay inside one cgo call; see fips.go */
// static int wc_HKDF_Unlocked(int type, const byte* inKey, word32 inKeySz,
//                             const byte* salt, word32 saltSz,
//                             const byte* info, word32 infoSz,
//                             byte* out, word32 outSz)
// {
//     int ret;
//     PRIVATE_KEY_UNLOCK();
//     ret = wc_HKDF(type, inKey, inKeySz, salt, saltSz, info, infoSz, out, outSz);
//     PRIVATE_KEY_LOCK();
//     return ret;
// }
import "C"
import (
    "unsafe"
)

type Hmac = C.struct_Hmac

/* Returns a 16-byte aligned Hmac struct allocated on the C heap (needed by SSE instructions) */
func Wc_HmacAllocAligned() *C.struct_Hmac {
    return C.wc_HmacAllocAligned()
}

func Wc_HmacFreeAllocAligned(hmac *C.struct_Hmac) {
    C.wc_HmacFreeAllocAligned(hmac)
}

func Wc_HmacInit(hmac *C.struct_Hmac, heap unsafe.Pointer, devId int) int {
    return int(C.wc_HmacInit(hmac, heap, C.int(devId)))
}

func Wc_HmacFree(hmac *C.struct_Hmac) {
    C.wc_HmacFree(hmac)
}

func Wc_HmacSetKey(hmac *C.struct_Hmac, hash int, key []byte, keySz int) int {
    if keySz < 0 || keySz > len(key) { return BAD_FUNC_ARG }
    var sanKey *C.uchar
    if len(key) > 0 {
        sanKey = (*C.uchar)(unsafe.Pointer(&key[0]))
    } else {
        sanKey = (*C.uchar)(unsafe.Pointer(nil))
    }
    return int(C.wc_HmacSetKey(hmac, C.int(hash), sanKey, C.word32(keySz)))
}

func Wc_HmacUpdate(hmac *C.struct_Hmac, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    var sanIn *C.uchar
    if len(in) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.uchar)(unsafe.Pointer(nil))
    }

    return int(C.wc_HmacUpdate(hmac, sanIn, C.word32(inSz)))
}

func Wc_HmacFinal(hmac *C.struct_Hmac, out []byte) int {
    if len(out) == 0 { return BAD_FUNC_ARG }
    return int(C.wc_HmacFinal(hmac, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_HKDF(hashType int, inputKey []byte, inputKeySz int, salt []byte,
             saltSz int, info []byte, infoSz int, out []byte, outSz int) int {
    if inputKeySz < 0 || inputKeySz > len(inputKey) { return BAD_FUNC_ARG }
    if saltSz < 0 || saltSz > len(salt) { return BAD_FUNC_ARG }
    if infoSz < 0 || infoSz > len(info) { return BAD_FUNC_ARG }
    if outSz < 0 || outSz > len(out) { return BAD_FUNC_ARG }
    if len(out) == 0 { return BAD_FUNC_ARG }
    // RFC 5869 permits a zero-length IKM (the Noise protocol's final
    // Split() step relies on this, passing ck as salt and "" as IKM).
    // Pass a NULL pointer to wolfCrypt rather than indexing an empty slice.
    var ikmPtr *C.uchar
    if len(inputKey) > 0 {
        ikmPtr = (*C.uchar)(unsafe.Pointer(&inputKey[0]))
    }
    var saltPtr *C.uchar
    if len(salt) > 0 {
        saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
    }
    var infoPtr *C.uchar
    if len(info) > 0 {
        infoPtr = (*C.uchar)(unsafe.Pointer(&info[0]))
    }
    return int(C.wc_HKDF_Unlocked(C.int(hashType), ikmPtr,
               C.word32(inputKeySz), saltPtr,
               C.word32(saltSz), infoPtr,
               C.word32(infoSz), (*C.uchar)(unsafe.Pointer(&out[0])),
               C.word32(outSz)))
}
