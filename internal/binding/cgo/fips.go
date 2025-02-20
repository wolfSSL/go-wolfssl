/* fips.go
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
// #include <wolfssl/wolfcrypt/types.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/fips_test.h>
// #ifndef WC_RNG_SEED_CB
// typedef int (*wc_RngSeed_Cb)(OS_Seed* os, byte* seed, word32 sz);
// int wc_SetSeed_Cb(wc_RngSeed_Cb cb) {
//      return -174;
//  }
// #endif
// #define WC_SPKRE_F(x,y) wolfCrypt_SetPrivateKeyReadEnable_fips((x),(y))
// #ifdef HAVE_FIPS
// int WC_PRIVATE_KEY_LOCK(void) {
//      return WC_SPKRE_F(0,WC_KEYTYPE_ALL);
// }
// int WC_PRIVATE_KEY_UNLOCK(void) {
//      return WC_SPKRE_F(1,WC_KEYTYPE_ALL);
// }
// #else
// int WC_PRIVATE_KEY_LOCK(void) {
//      return -174;
// }
// int WC_PRIVATE_KEY_UNLOCK(void) {
//      return -174;
// }
// int wc_RunAllCast_fips(void) {
//      return -174;
// }
// #endif
import "C"

func Wc_SetDefaultSeed_Cb() int {
    return int(C.wc_SetSeed_Cb((C.wc_RngSeed_Cb)(C.wc_GenerateSeed)))
}

func PRIVATE_KEY_LOCK() int {
    return int(C.WC_PRIVATE_KEY_LOCK())
}

func PRIVATE_KEY_UNLOCK() int {
    return int(C.WC_PRIVATE_KEY_UNLOCK())
}

func Wc_RunAllCast_fips() int {
    return int(C.wc_RunAllCast_fips())
}
