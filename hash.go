/* hash.go
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

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/hash.h>
// #ifdef NO_MD5
// #define WC_MD5_DIGEST_SIZE 1
// int wc_Md5Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifdef NO_SHA
// #define WC_SHA_DIGEST_SIZE 1
// int wc_ShaHash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifdef NO_SHA256
// int wc_Sha256Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifndef WOLFSSL_SHA384
// #define WC_SHA384_DIGEST_SIZE 1
// int wc_Sha384Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifndef WOLFSSL_SHA512
// int wc_Sha512Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
import "C"
import (
    "unsafe"
)

const WC_MD5_DIGEST_SIZE = int(C.WC_MD5_DIGEST_SIZE)
const WC_SHA_DIGEST_SIZE = int(C.WC_SHA_DIGEST_SIZE)
const WC_SHA256_DIGEST_SIZE = int(C.WC_SHA256_DIGEST_SIZE)
const WC_SHA384_DIGEST_SIZE = int(C.WC_SHA384_DIGEST_SIZE)
const WC_SHA512_DIGEST_SIZE = int(C.WC_SHA512_DIGEST_SIZE)

const WC_SHA256 = int(C.WC_SHA256)

func Wc_Md5Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Md5Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_ShaHash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_ShaHash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha256Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Sha256Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha384Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Sha384Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha512Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Sha512Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}
