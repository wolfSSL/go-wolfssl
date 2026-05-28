/* misc_test.go
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
	"bytes"
	"testing"
)

func TestConstantCompare_Match(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x03}
	if got := ConstantCompare(a, b, 3); got != 1 {
		t.Fatalf("equal slices: got %d, want 1", got)
	}
}

func TestConstantCompare_Mismatch(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x04}
	if got := ConstantCompare(a, b, 3); got != 0 {
		t.Fatalf("different slices: got %d, want 0", got)
	}
}

func TestConstantCompare_PartialLength(t *testing.T) {
	// Equal in first 2 bytes, differ in 3rd.
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x04}
	if got := ConstantCompare(a, b, 2); got != 1 {
		t.Fatalf("equal-prefix length=2: got %d, want 1", got)
	}
}

// zeroMemory must zero the slice and must not crash on empty input.
func TestZeroMemory_ZerosSlice(t *testing.T) {
	buf := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	zeroMemory(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %#x", i, b)
		}
	}
}

func TestZeroMemory_EmptySlice_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zeroMemory on empty slice should not panic: %v", r)
		}
	}()
	zeroMemory(nil)
	zeroMemory([]byte{})
}

func TestZeroMemory_LargeSlice(t *testing.T) {
	buf := bytes.Repeat([]byte{0xff}, 4096)
	zeroMemory(buf)
	for i := range buf {
		if buf[i] != 0 {
			t.Fatalf("byte %d not zeroed in large buffer", i)
		}
	}
}
