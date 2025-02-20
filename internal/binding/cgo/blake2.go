/* blake2s.go
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
// #include <wolfssl/wolfcrypt/hash.h>
// #include <wolfssl/wolfcrypt/blake2.h>
// #ifndef HAVE_BLAKE2S
// typedef struct Blake2s {} Blake2s;
// void wc_Blake2s_HMAC(byte *out, const byte *in, const byte *key, word32 outlen, word32 inlen, word32 keylen) {
//      return;
// }
// int wc_InitBlake2s(Blake2s* b, word32 digestSz) {
//      return -174;
//  }
// int wc_InitBlake2s_WithKey(Blake2s* b, word32 digestSz, byte *key, word32 keylen) {
//      return -174;
//  }
// int wc_Blake2sUpdate(Blake2s* b2s, byte* data, word32 sz) {
//      return -174;
//  }
// int wc_Blake2sFinal(Blake2s* b2s, byte* data, word32 reqSz) {
//      return -174;
//  }
// #endif
import "C"
import (
    "unsafe"
)

const WC_BLAKE2S_256_DIGEST_SIZE = 32
const WC_BLAKE2S_128_DIGEST_SIZE = 16

const WC_BLAKE2S_256_BLOCK_SIZE = 64

type Blake2s = C.struct_Blake2s

func Wc_InitBlake2s(blake2s *C.struct_Blake2s, digestSz int) int {
    return int(C.wc_InitBlake2s(blake2s, C.word32(digestSz)))
}

func Wc_InitBlake2s_WithKey(blake2s *C.struct_Blake2s, digestSz int, key []byte) int {
    return int(C.wc_InitBlake2s_WithKey(blake2s, C.word32(digestSz),
               (*C.uchar)(unsafe.Pointer(&key[0])), C.word32(len(key))))
}

func Wc_Blake2sUpdate(blake2s *C.struct_Blake2s, in []byte, sz int) int {
    var sanIn *C.uchar
    if len(in) > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.uchar)(unsafe.Pointer(nil))
    }

    return int(C.wc_Blake2sUpdate(blake2s, sanIn, C.word32(sz)))
}

func Wc_Blake2sFinal(blake2s *C.struct_Blake2s, out []byte, requestSz int) int {
    return int(C.wc_Blake2sFinal(blake2s, (*C.uchar)(unsafe.Pointer(&out[0])),
               C.word32(requestSz)))
}

func Wc_Blake2s_HMAC(out []byte, in, key []byte, outlen int) {
    var state Blake2s
    var x_key [WC_BLAKE2S_256_BLOCK_SIZE]byte
    var i_hash [WC_BLAKE2S_256_DIGEST_SIZE]byte

    i := 0

    inlen := len(in)
    keylen := len(key)

    if outlen != WC_BLAKE2S_256_DIGEST_SIZE {
       return
   }

    if keylen > WC_BLAKE2S_256_BLOCK_SIZE {
        Wc_InitBlake2s(&state, WC_BLAKE2S_256_DIGEST_SIZE)
        Wc_Blake2sUpdate(&state, key, keylen)
        Wc_Blake2sFinal(&state, x_key[:], 0)
    } else {
        copy(x_key[:], key)
        for i = keylen; i < WC_BLAKE2S_256_BLOCK_SIZE; i++ {
            x_key[i] = 0
        }
    }

    for i = 0; i < WC_BLAKE2S_256_BLOCK_SIZE; i++ {
        x_key[i] ^= 0x36
    }

    Wc_InitBlake2s(&state, WC_BLAKE2S_256_DIGEST_SIZE)
    Wc_Blake2sUpdate(&state, x_key[:], WC_BLAKE2S_256_BLOCK_SIZE)
    Wc_Blake2sUpdate(&state, in, inlen)
    Wc_Blake2sFinal(&state, i_hash[:], 0)

    for i = 0; i < WC_BLAKE2S_256_BLOCK_SIZE; i++ {
        x_key[i] ^= 0x5c ^ 0x36
    }

    Wc_InitBlake2s(&state, WC_BLAKE2S_256_DIGEST_SIZE)
    Wc_Blake2sUpdate(&state, x_key[:], WC_BLAKE2S_256_BLOCK_SIZE)
    Wc_Blake2sUpdate(&state, i_hash[:], WC_BLAKE2S_256_DIGEST_SIZE)
    Wc_Blake2sFinal(&state, i_hash[:], 0)

    copy(out[:], i_hash[:])
    zeroMemory(i_hash[:])
    zeroMemory(x_key[:])
}
