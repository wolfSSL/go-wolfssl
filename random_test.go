/* random_test.go
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

func newRng(t *testing.T) *WC_RNG {
	t.Helper()
	var rng WC_RNG
	ret := Wc_InitRng(&rng)
	skipIfNotCompiledIn(t, ret, "RNG")
	if ret != 0 {
		t.Fatalf("Wc_InitRng returned %d", ret)
	}
	t.Cleanup(func() { Wc_FreeRng(&rng) })
	return &rng
}

func TestRNG_GeneratesNonZero(t *testing.T) {
	rng := newRng(t)
	buf := make([]byte, 64)
	if ret := Wc_RNG_GenerateBlock(rng, buf, len(buf)); ret != 0 {
		t.Fatalf("Wc_RNG_GenerateBlock returned %d", ret)
	}
	if bytes.Equal(buf, make([]byte, 64)) {
		t.Fatal("RNG returned all zeros — implausible (1 in 2^512)")
	}
}

// Two consecutive RNG draws should not match.
func TestRNG_NotRepeating(t *testing.T) {
	rng := newRng(t)
	a := make([]byte, 32)
	b := make([]byte, 32)
	if ret := Wc_RNG_GenerateBlock(rng, a, len(a)); ret != 0 {
		t.Fatalf("first GenerateBlock: %d", ret)
	}
	if ret := Wc_RNG_GenerateBlock(rng, b, len(b)); ret != 0 {
		t.Fatalf("second GenerateBlock: %d", ret)
	}
	// Collision probability for two 32-byte draws: 2^-256.
	if bytes.Equal(a, b) {
		t.Fatal("two RNG draws returned identical 32 bytes — implausible")
	}
}

// sz=0 should return 0 (not error, not panic).
func TestRNG_ZeroSize_ReturnsZero(t *testing.T) {
	rng := newRng(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("sz=0 should not panic: %v", r)
		}
	}()
	if ret := Wc_RNG_GenerateBlock(rng, make([]byte, 4), 0); ret != 0 {
		t.Fatalf("expected ret=0 for sz=0, got %d", ret)
	}
}

// Boundary: sz > len(b) must be caught at wrapper (wc can't see Go slice len).
func TestRNG_OversizedSz_Rejected(t *testing.T) {
	rng := newRng(t)
	b := make([]byte, 16)
	if ret := Wc_RNG_GenerateBlock(rng, b, 1<<20); ret == 0 {
		t.Fatal("expected error for sz > len(b)")
	}
}
