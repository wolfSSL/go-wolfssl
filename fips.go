/* fips.go
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
// #include <wolfssl/wolfcrypt/types.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/fips_test.h>
// #ifndef WC_RNG_SEED_CB
// typedef int (*wc_RngSeed_Cb)(OS_Seed* os, byte* seed, word32 sz);
// int wc_SetSeed_Cb(wc_RngSeed_Cb cb) {
//      return -174;
//  }
// #endif
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
//        printf("In-core integrity hash check failure, copy above hash\n");
//        printf("into verifyCore[] in wolfssl/wolfcrypt/src/fips_test.c and rebuild\n");
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
import "fmt"

func Wc_SetDefaultFips_Cb() {
    C.wc_SetDefaultFips_Cb()
}

func Wc_SetDefaultSeed_Cb() int {
    return int(C.wc_SetSeed_Cb((C.wc_RngSeed_Cb)(C.wc_GenerateSeed)))
}

// FIPS private-key gate.
//
// wolfCrypt's FIPS APIs refuse to read private-key material unless the
// calling thread has enabled it. In userspace builds that enable flag is
// per-OS-thread instead of process-wide.
//
// A goroutine is pinned to its OS thread only for the duration of a single
// cgo call. Calling PRIVATE_KEY_UNLOCK, then the wolfCrypt operation, then
// PRIVATE_KEY_LOCK as three separate cgo calls therefore leaves a window in
// which the scheduler can move the goroutine to another thread. The
// operation then runs on a thread whose counter was never incremented and
// fails with FIPS_PRIVATE_KEY_LOCKED_E (-287), while the thread that took
// the unlock is left permanently unlocked.
//
// The Wc_* wrappers in this go-wolfssl avoid that by performing unlock,
// operation and lock inside one static C helper (wc_HKDF_Unlocked,
// wc_PBKDF2_Unlocked, ...).
//
// PRIVATE_KEY_LOCK and PRIVATE_KEY_UNLOCK are exported but they act on the
// calling OS thread's counter, so any direct callers must hold
// runtime.LockOSThread() across the entire unlock/operation/lock sequence.
func PRIVATE_KEY_LOCK() int {
    return int(C.WC_PRIVATE_KEY_LOCK())
}

// See PRIVATE_KEY_LOCK for the threading requirements.
func PRIVATE_KEY_UNLOCK() int {
    return int(C.WC_PRIVATE_KEY_UNLOCK())
}

func Wc_RunAllCast_fips() int {
    return int(C.wc_RunAllCast_fips())
}

func init() {
    if ret := C.wolfCrypt_Init(); ret != 0 {
        panic(fmt.Sprintf("wolfSSL: wolfCrypt_Init failed: %d", ret))
    }
    Wc_SetDefaultFips_Cb()
    Wc_SetDefaultSeed_Cb()

    if ret := Wc_RunAllCast_fips(); ret != 0 && ret != -174 {
        panic(fmt.Sprintf("wolfSSL: wc_RunAllCast_fips failed: %d CAST(s) failed", ret))
    }
}
