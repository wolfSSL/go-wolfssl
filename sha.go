/* sha.go
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

package wolfSSL

// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/sha256.h>
import "C"
import (
    "unsafe"
)

type Wc_Sha256 = C.struct_wc_Sha256

func Wc_InitSha256_ex(sha *C.struct_wc_Sha256, heap unsafe.Pointer, devId int) int {
    return int(C.wc_InitSha256_ex(sha, heap, C.int(devId)))
}

func Wc_Sha256Free(sha *C.struct_wc_Sha256) {
    C.wc_Sha256Free(sha)
}

func Wc_Sha256Update(sha *C.struct_wc_Sha256, in []byte, inSz int) int {
    var sanIn *C.uchar
    if len(in) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.uchar)(unsafe.Pointer(nil))
    }

    return int(C.wc_Sha256Update(sha, sanIn, C.word32(inSz)))
}

func Wc_Sha256Final(sha *C.struct_wc_Sha256, out []byte) int {
    return int(C.wc_Sha256Final(sha, (*C.uchar)(unsafe.Pointer(&out[0]))))
}
