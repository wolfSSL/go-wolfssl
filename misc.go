/* misc.go
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
// #include <wolfssl/wolfcrypt/error-crypt.h>
// #include <wolfssl/wolfcrypt/memory.h>
import "C"
import "unsafe"

const BAD_FUNC_ARG = int(C.BAD_FUNC_ARG)
const LENGTH_ONLY_E = int(C.LENGTH_ONLY_E)

func ConstantCompare(a, b []byte, length int) int {
    if length < 0 || length > len(a) || length > len(b) { return 0 }
    var result byte = 0
    for i := 0; i < length; i++ {
        result |= a[i] ^ b[i]
    }

    if result == 0 {
        return 1
    } else {
        return 0
    }
}

func zeroMemory(b []byte) {
    if len(b) > 0 {
        C.wc_ForceZero(unsafe.Pointer(&b[0]), C.size_t(len(b)))
    }
}
