/* sha256.go
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

package sha256

import (
	"fmt"
	"hash"
	"runtime"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// The size of a SHA-256 checksum in bytes.
const Size = 32

// The block size of SHA-256 in bytes.
const BlockSize = 64

// Sum256 returns the SHA-256 checksum of the data.
func Sum256(data []byte) [Size]byte {
	var sha wolfSSL.Wc_Sha256
	if ret := wolfSSL.Wc_InitSha256_ex(&sha, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/sha256: Wc_InitSha256_ex: %d", ret))
	}
	defer wolfSSL.Wc_Sha256Free(&sha)
	if len(data) > 0 {
		if ret := wolfSSL.Wc_Sha256Update(&sha, data, len(data)); ret != 0 {
			panic(fmt.Sprintf("wolfSSL/sha256: Wc_Sha256Update: %d", ret))
		}
	}
	var out [Size]byte
	if ret := wolfSSL.Wc_Sha256Final(&sha, out[:]); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/sha256: Wc_Sha256Final: %d", ret))
	}
	return out
}

// New returns a new hash.Hash computing the SHA-256 checksum.
func New() hash.Hash {
	d := &digest{}
	if ret := wolfSSL.Wc_InitSha256_ex(&d.sha, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/sha256: Wc_InitSha256_ex: %d", ret))
	}
	runtime.SetFinalizer(d, func(d *digest) { wolfSSL.Wc_Sha256Free(&d.sha) })
	return d
}

// digest is the wolfCrypt-backed hash.Hash implementation. Named to
// match crypto/sha256's internal "digest" type so traces are familiar.
type digest struct {
	sha wolfSSL.Wc_Sha256
}

// Size returns the number of bytes Sum will append.
func (d *digest) Size() int { return Size }

// BlockSize returns the hash's underlying block size.
func (d *digest) BlockSize() int { return BlockSize }

// Write adds more data to the running hash.
func (d *digest) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if ret := wolfSSL.Wc_Sha256Update(&d.sha, p, len(p)); ret != 0 {
		return 0, fmt.Errorf("wolfSSL/sha256: Wc_Sha256Update: %d", ret)
	}
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(b []byte) []byte {
	var clone wolfSSL.Wc_Sha256
	if ret := wolfSSL.Wc_InitSha256_ex(&clone, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/sha256: Sum InitSha256_ex: %d", ret))
	}
	if ret := wolfSSL.Wc_Sha256Copy(&d.sha, &clone); ret != 0 {
		wolfSSL.Wc_Sha256Free(&clone)
		panic(fmt.Sprintf("wolfSSL/sha256: Sum Wc_Sha256Copy: %d", ret))
	}
	var out [Size]byte
	if ret := wolfSSL.Wc_Sha256Final(&clone, out[:]); ret != 0 {
		wolfSSL.Wc_Sha256Free(&clone)
		panic(fmt.Sprintf("wolfSSL/sha256: Sum Wc_Sha256Final: %d", ret))
	}
	wolfSSL.Wc_Sha256Free(&clone)
	return append(b, out[:]...)
}

// Reset discards any data previously written.
func (d *digest) Reset() {
	wolfSSL.Wc_Sha256Free(&d.sha)
	if ret := wolfSSL.Wc_InitSha256_ex(&d.sha, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/sha256: Reset Wc_InitSha256_ex: %d", ret))
	}
}
