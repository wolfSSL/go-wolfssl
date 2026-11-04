/* version.go
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

package wolftls

// /* cgo directives for this package live in conn.go. */
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
//
// static int wolftls_native_min_version(WOLFSSL_CTX* ctx, int v) {
//     switch (v) {
//     case 0x0301: return wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1);
//     case 0x0302: return wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_1);
//     case 0x0303: return wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
//     case 0x0304: return wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
//     default:     return BAD_FUNC_ARG;
//     }
// }
// static int wolftls_highest_version(void) {
// #if defined(WOLFSSL_TLS13)
//     return 0x0304;
// #elif !defined(WOLFSSL_NO_TLS12)
//     return 0x0303;
// #else
//     return 0x0302;
// #endif
// }
import "C"

import (
	"fmt"
	"unsafe"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// ctxSetMinVersion applies a TLS version floor to ctx. Builds without the
// OpenSSL compatibility layer fall back to wolfSSL_CTX_SetMinVersion.
func ctxSetMinVersion(ctx *wolfSSL.WOLFSSL_CTX, v uint16) error {
	ret := wolfSSL.WolfSSL_CTX_set_min_proto_version(ctx, int(v))
	if ret == int(C.NOT_COMPILED_IN) {
		ret = int(C.wolftls_native_min_version((*C.WOLFSSL_CTX)(unsafe.Pointer(ctx)), C.int(v)))
	}
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		return fmt.Errorf("wolftls: set_min_proto_version(0x%x) rejected: %d", v, ret)
	}
	return nil
}

// ctxSetMaxVersion applies a TLS version ceiling to ctx. Without the
// OpenSSL compatibility layer only a ceiling at the build's highest
// version (which needs no change) can be honored; lower ones are an error.
func ctxSetMaxVersion(ctx *wolfSSL.WOLFSSL_CTX, v uint16) error {
	ret := wolfSSL.WolfSSL_CTX_set_max_proto_version(ctx, int(v))
	if ret == int(C.NOT_COMPILED_IN) {
		if int(v) >= int(C.wolftls_highest_version()) && v <= VersionTLS13 {
			return nil
		}
		return fmt.Errorf("wolftls: MaxVersion 0x%x requires wolfSSL built with OPENSSL_EXTRA", v)
	}
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		return fmt.Errorf("wolftls: set_max_proto_version(0x%x) rejected: %d", v, ret)
	}
	return nil
}
