/* hmac.go
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
// #include <wolfssl/wolfcrypt/hmac.h>
import "C"
import (
    "unsafe"
)

type Hmac = C.struct_Hmac

func Wc_HmacInit(hmac *C.struct_Hmac, heap unsafe.Pointer, devId int) int {
    return int(C.wc_HmacInit(hmac, heap, C.int(devId)))
}

func Wc_HmacFree(hmac *C.struct_Hmac) {
    C.wc_HmacFree(hmac)
}

func Wc_HmacSetKey(hmac *C.struct_Hmac, hash int, key []byte, keySz int) int {
    var sanKey *C.uchar
    if len(key) > 0 {
        sanKey = (*C.uchar)(unsafe.Pointer(&key[0]))
    } else {
        sanKey = (*C.uchar)(unsafe.Pointer(nil))
    }
    return int(C.wc_HmacSetKey(hmac, C.int(hash), sanKey, C.word32(keySz)))
}

func Wc_HmacUpdate(hmac *C.struct_Hmac, in []byte, inSz int) int {
    var sanIn *C.uchar
    if len(in) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.uchar)(unsafe.Pointer(nil))
    }

    return int(C.wc_HmacUpdate(hmac, sanIn, C.word32(inSz)))
}

func Wc_HmacFinal(hmac *C.struct_Hmac, out []byte) int {
    return int(C.wc_HmacFinal(hmac, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_HKDF(hashType int, inputKey []byte, inputKeySz int, salt []byte,
             saltSz int, info []byte, infoSz int, out []byte, outSz int) int {
    return int(C.wc_HKDF(C.int(hashType), (*C.uchar)(unsafe.Pointer(&inputKey[0])),
               C.word32(inputKeySz), (*C.uchar)(unsafe.Pointer(&salt[0])),
               C.word32(saltSz), (*C.uchar)(unsafe.Pointer(&info[0])),
               C.word32(infoSz), (*C.uchar)(unsafe.Pointer(&out[0])),
               C.word32(outSz)))
}
