/* keys.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

package wolfx509

import (
	"github.com/wolfssl/go-wolfssl/handles"
)

// GenerateP256Key returns a fresh P-256 (secp256r1) ECC key pair. Mirrors
// the role of crypto/ecdsa.GenerateKey(elliptic.P256(), rand.Reader). The
// caller owns the returned key and must Free it.
func GenerateP256Key() (*handles.EccKey, error) {
	return handles.GenerateP256Key()
}
