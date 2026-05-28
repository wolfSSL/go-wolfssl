/* ssl_test.go
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

import (
	"strings"
	"testing"
)

// ERR_error_string must accept nil data and return a non-empty string.
func TestERR_ErrorString_NoPanicOnEmptyData(t *testing.T) {
	got := WolfSSL_ERR_error_string(BAD_FUNC_ARG, nil)
	if got == "" {
		t.Fatal("expected non-empty error string for BAD_FUNC_ARG")
	}
}

// Same with an empty (non-nil) slice.
func TestERR_ErrorString_NoPanicOnEmptySlice(t *testing.T) {
	WolfSSL_ERR_error_string(0, []byte{})
}

// ERR_error_string for a known code must return a printable string.
func TestERR_ErrorString_NonEmptyForKnownCode(t *testing.T) {
	got := WolfSSL_ERR_error_string(BAD_FUNC_ARG, nil)
	if len(got) < 4 {
		t.Fatalf("error string too short: %q", got)
	}
	if strings.Contains(got, "\x00") {
		t.Fatalf("error string contains nul: %q", got)
	}
}

// lib_version should return a non-empty version string.
func TestWolfSSL_LibVersion(t *testing.T) {
	v := WolfSSL_lib_version()
	if v == "" {
		t.Fatal("WolfSSL_lib_version returned empty string")
	}
}
