/* blake2_test.go
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

func TestBlake2s_KnownAnswer(t *testing.T) {
	var ctx Blake2s
	if ret := Wc_InitBlake2s(&ctx, WC_BLAKE2S_256_DIGEST_SIZE); ret != 0 {
		if ret == notCompiledIn {
			t.Skip("Blake2 not compiled in")
		}
		t.Fatalf("InitBlake2s: %d", ret)
	}

	in := []byte("abc")
	if ret := Wc_Blake2sUpdate(&ctx, in, len(in)); ret != 0 {
		t.Fatalf("Update: %d", ret)
	}
	out := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	if ret := Wc_Blake2sFinal(&ctx, out, WC_BLAKE2S_256_DIGEST_SIZE); ret != 0 {
		t.Fatalf("Final: %d", ret)
	}
	// Known Blake2s-256("abc"):
	want := []byte{
		0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
		0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
		0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
		0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("Blake2s(\"abc\") mismatch:\n got:  %x\n want: %x", out, want)
	}
}

// blake2sBuiltIn returns true if Blake2 is compiled into the linked wolfSSL.
func blake2sBuiltIn() bool {
	var probe Blake2s
	return Wc_InitBlake2s(&probe, WC_BLAKE2S_256_DIGEST_SIZE) == 0
}

// Blake2s_HMAC must produce non-zero output for valid inputs.
func TestBlake2s_HMAC_ProducesNonZeroOutput(t *testing.T) {
	if !blake2sBuiltIn() {
		t.Skip("Blake2 not compiled in")
	}
	out := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	in := []byte("message to MAC")
	key := []byte("secret key")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Blake2s_HMAC panicked: %v", r)
		}
	}()
	Wc_Blake2s_HMAC(out, in, key, WC_BLAKE2S_256_DIGEST_SIZE)
	if bytes.Equal(out, make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)) {
		t.Fatal("Blake2s_HMAC returned all zeros")
	}
}

// Different keys must produce different MACs.
func TestBlake2s_HMAC_KeyDependent(t *testing.T) {
	if !blake2sBuiltIn() {
		t.Skip("Blake2 not compiled in")
	}
	in := []byte("same message")
	out1 := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	out2 := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Blake2s_HMAC panicked: %v", r)
		}
	}()
	Wc_Blake2s_HMAC(out1, in, []byte("key1"), WC_BLAKE2S_256_DIGEST_SIZE)
	Wc_Blake2s_HMAC(out2, in, []byte("key2"), WC_BLAKE2S_256_DIGEST_SIZE)
	if bytes.Equal(out1, out2) {
		t.Fatal("different keys produced identical MACs")
	}
}

// Wc_Blake2s_HMAC with invalid outlen should not panic or write garbage.
func TestBlake2s_HMAC_InvalidOutlen_NoPanic(t *testing.T) {
	out := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("invalid outlen should be handled, not panic: %v", r)
		}
	}()
	// requestSz=0 should not produce useful output but must not panic.
	Wc_Blake2s_HMAC(out, []byte("data"), []byte("key"), 0)
}
