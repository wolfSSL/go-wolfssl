/* fips.go
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
// void fipsCb(int ok, int err, const char* hash)
// {
//    printf("in my Fips callback, ok = %d, err = %d\n", ok, err);
//    printf("hash = %s\n", hash);
//
//    if (err == -203) {
//        printf("In core integrity hash check failure, copy above hash\n");
//        printf("into verifyCore[] in fips_test.c and rebuild\n");
//    }
// }
// void wc_SetDefaultFips_Cb(void) {
// 	wolfCrypt_SetCb_fips(fipsCb);
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
// void wc_SetDefaultFips_Cb(void) {
// 	return;
// }
// #endif
import "C"

func Wc_SetDefaultFips_Cb() {
    C.wc_SetDefaultFips_Cb()
}

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
