/* init.go
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

package wolftls

import (
	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// wolfSSLInit initializes the underlying wolfSSL library.
func wolfSSLInit() {
	wolfSSL.WolfSSL_Init()
}

// Cleanup releases global wolfSSL library resources. Call at most once,
// only after all Conn objects have been closed. Most long-running programs
// (e.g. Tailscale) never need to call this.
func Cleanup() {
	wolfSSL.WolfSSL_Cleanup()
}
