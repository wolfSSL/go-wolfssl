/* hash.go
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
// #define WC_SHA256_DIGEST_SIZE 1
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
// #define WC_SHA512_DIGEST_SIZE 1
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
    if inputSz < 0 || inputSz > len(input) { return BAD_FUNC_ARG }
    if len(output) < WC_MD5_DIGEST_SIZE { return BAD_FUNC_ARG }
    var sanIn *C.uchar
    if len(input) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&input[0]))
    }
    return int(C.wc_Md5Hash(sanIn,
               C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_ShaHash(input []byte, inputSz int, output []byte) int {
    if inputSz < 0 || inputSz > len(input) { return BAD_FUNC_ARG }
    if len(output) < WC_SHA_DIGEST_SIZE { return BAD_FUNC_ARG }
    var sanIn *C.uchar
    if len(input) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&input[0]))
    }
    return int(C.wc_ShaHash(sanIn,
               C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha256Hash(input []byte, inputSz int, output []byte) int {
    if inputSz < 0 || inputSz > len(input) { return BAD_FUNC_ARG }
    if len(output) < WC_SHA256_DIGEST_SIZE { return BAD_FUNC_ARG }
    var sanIn *C.uchar
    if len(input) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&input[0]))
    }
    return int(C.wc_Sha256Hash(sanIn,
               C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha384Hash(input []byte, inputSz int, output []byte) int {
    if inputSz < 0 || inputSz > len(input) { return BAD_FUNC_ARG }
    if len(output) < WC_SHA384_DIGEST_SIZE { return BAD_FUNC_ARG }
    var sanIn *C.uchar
    if len(input) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&input[0]))
    }
    return int(C.wc_Sha384Hash(sanIn,
               C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha512Hash(input []byte, inputSz int, output []byte) int {
    if inputSz < 0 || inputSz > len(input) { return BAD_FUNC_ARG }
    if len(output) < WC_SHA512_DIGEST_SIZE { return BAD_FUNC_ARG }
    var sanIn *C.uchar
    if len(input) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&input[0]))
    }
    return int(C.wc_Sha512Hash(sanIn,
               C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}
