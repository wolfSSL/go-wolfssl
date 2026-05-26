/* random.go
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
// #include <wolfssl/wolfcrypt/random.h>
// #ifdef WC_NO_RNG
// typedef struct WC_RNG {} WC_RNG;
// int wc_InitRng(WC_RNG* rng) {
//      return -174;
// }
// int wc_FreeRng(WC_RNG* rng) {
//      return -174;
// }
// int wc_RNG_GenerateBlock(WC_RNG* rng, byte* b, word32 sz) {
//      return -174;
// }
// WC_RNG* wc_rng_new(byte* nonce, word32 nonceSz, void* heap) {
//      (void)nonce; (void)nonceSz; (void)heap;
//      return NULL;
// }
// void wc_rng_free(WC_RNG* rng) { (void)rng; }
// #endif
import "C"
import (
    "unsafe"
)

type WC_RNG = C.struct_WC_RNG

func Wc_InitRng(rng *C.struct_WC_RNG) int {
    return int(C.wc_InitRng(rng))
}

func Wc_FreeRng(rng *C.struct_WC_RNG) int {
    return int(C.wc_FreeRng(rng))
}

func Wc_RNG_GenerateBlock(rng *C.struct_WC_RNG, b []byte, sz int) int {
    if sz < 0 || sz > len(b) { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_RNG_GenerateBlock(rng, (*C.uchar)(unsafe.Pointer(&b[0])),
               C.word32(sz)))
}

func Wc_RNG_New() *C.struct_WC_RNG {
    return C.wc_rng_new(nil, 0, nil)
}

func Wc_RNG_Free(rng *C.struct_WC_RNG) {
    C.wc_rng_free(rng)
}
