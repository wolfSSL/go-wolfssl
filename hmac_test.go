/* hmac_test.go
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
	"encoding/hex"
	"testing"
)

// hmacOneShot computes HMAC-Hash and returns the digest.
func hmacOneShot(t *testing.T, hashType int, key, msg []byte, digestSize int) []byte {
	t.Helper()
	hmac := Wc_HmacAllocAligned()
	if hmac == nil {
		t.Skip("HMAC not compiled in")
	}
	defer Wc_HmacFreeAllocAligned(hmac)
	ret := Wc_HmacInit(hmac, nil, INVALID_DEVID)
	skipIfNotCompiledIn(t, ret, "HMAC")
	if ret != 0 {
		t.Fatalf("HmacInit returned %d", ret)
	}
	defer Wc_HmacFree(hmac)
	ret = Wc_HmacSetKey(hmac, hashType, key, len(key))
	skipIfNotCompiledIn(t, ret, "HMAC hash type")
	if ret != 0 {
		t.Fatalf("HmacSetKey returned %d", ret)
	}
	if ret := Wc_HmacUpdate(hmac, msg, len(msg)); ret != 0 {
		t.Fatalf("HmacUpdate returned %d", ret)
	}
	out := make([]byte, digestSize)
	if ret := Wc_HmacFinal(hmac, out); ret != 0 {
		t.Fatalf("HmacFinal returned %d", ret)
	}
	return out
}

// RFC 4231 Test Case 1: HMAC-SHA256 with a digest-sized output buffer.
func TestHmacFinal_AllowsPerHashDigestSize(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	msg := []byte("Hi There")
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

	got := hmacOneShot(t, WC_SHA256, key, msg, WC_SHA256_DIGEST_SIZE)
	if hex.EncodeToString(got) != want {
		t.Fatalf("HMAC-SHA256 mismatch:\n  got:  %x\n  want: %s", got, want)
	}
}

// HMAC-SHA-256 known answer (RFC 4231 test case 2).
func TestHmac_RFC4231_Vectors(t *testing.T) {
	cases := []struct {
		name       string
		key        string
		data       string
		wantSHA256 string
	}{
		{
			name:       "case2_what_do_ya_want",
			key:        "Jefe",
			data:       "what do ya want for nothing?",
			wantSHA256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hmacOneShot(t, WC_SHA256, []byte(tc.key), []byte(tc.data), WC_SHA256_DIGEST_SIZE)
			if hex.EncodeToString(got) != tc.wantSHA256 {
				t.Fatalf("got %x, want %s", got, tc.wantSHA256)
			}
		})
	}
}

// HmacFinal must accept an exactly-digest-sized buffer.
func TestHmacFinal_DoesNotRequireMaxDigestSize(t *testing.T) {
	hmac := Wc_HmacAllocAligned()
	defer Wc_HmacFreeAllocAligned(hmac)
	if ret := Wc_HmacInit(hmac, nil, INVALID_DEVID); ret != 0 {
		t.Fatalf("HmacInit: %d", ret)
	}
	defer Wc_HmacFree(hmac)
	key := []byte("test-key")
	if ret := Wc_HmacSetKey(hmac, WC_SHA256, key, len(key)); ret != 0 {
		t.Fatalf("HmacSetKey: %d", ret)
	}
	if ret := Wc_HmacUpdate(hmac, []byte("data"), 4); ret != 0 {
		t.Fatalf("HmacUpdate: %d", ret)
	}
	// Exactly digest-sized buffer for SHA-256 (32 bytes) — should succeed.
	out := make([]byte, WC_SHA256_DIGEST_SIZE)
	if ret := Wc_HmacFinal(hmac, out); ret != 0 {
		t.Fatalf("HmacFinal with digest-sized buffer should succeed, got %d", ret)
	}
}

// HmacFinal with empty output should not panic.
func TestHmacFinal_EmptyOutput_DoesNotPanic(t *testing.T) {
	hmac := Wc_HmacAllocAligned()
	defer Wc_HmacFreeAllocAligned(hmac)
	if ret := Wc_HmacInit(hmac, nil, INVALID_DEVID); ret != 0 {
		t.Fatalf("HmacInit: %d", ret)
	}
	defer Wc_HmacFree(hmac)
	if ret := Wc_HmacSetKey(hmac, WC_SHA256, []byte("k"), 1); ret != 0 {
		t.Fatalf("HmacSetKey: %d", ret)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("empty out should error, not panic: %v", r)
		}
	}()
	if ret := Wc_HmacFinal(hmac, []byte{}); ret == 0 {
		t.Fatal("expected error on empty output, got success")
	}
}

// HKDF must accept an empty IKM (RFC 5869; Noise protocol Split relies on it).
func TestHKDF_EmptyIKM_RFC5869(t *testing.T) {
	salt := []byte("not-empty-salt")
	info := []byte("context")
	out := make([]byte, 32)

	ret := Wc_HKDF(WC_SHA256, nil, 0, salt, len(salt), info, len(info), out, len(out))
	skipIfNotCompiledIn(t, ret, "HKDF")
	if ret != 0 {
		t.Fatalf("HKDF with empty IKM should succeed per RFC 5869, got %d", ret)
	}
	// Output should be deterministic and non-zero.
	if bytes.Equal(out, make([]byte, 32)) {
		t.Fatal("HKDF returned all zeros — likely no output produced")
	}
}

// HKDF RFC 5869 Test Case 1: SHA-256 standard.
func TestHKDF_RFC5869_TestCase1(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	wantOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	out := make([]byte, 42)
	ret := Wc_HKDF(WC_SHA256, ikm, len(ikm), salt, len(salt), info, len(info), out, len(out))
	skipIfNotCompiledIn(t, ret, "HKDF")
	if ret != 0 {
		t.Fatalf("HKDF returned %d", ret)
	}
	if hex.EncodeToString(out) != wantOKM {
		t.Fatalf("HKDF OKM mismatch:\n  got:  %x\n  want: %s", out, wantOKM)
	}
}

// HKDF with empty salt is also valid per RFC 5869.
func TestHKDF_EmptySalt_OK(t *testing.T) {
	ikm := bytes.Repeat([]byte{0xaa}, 22)
	out := make([]byte, 32)
	ret := Wc_HKDF(WC_SHA256, ikm, len(ikm), nil, 0, nil, 0, out, len(out))
	skipIfNotCompiledIn(t, ret, "HKDF")
	if ret != 0 {
		t.Fatalf("HKDF with empty salt+info should succeed, got %d", ret)
	}
}

// Boundary: oversized inputKeySz must not let wc read past Go slice.
func TestHKDF_OversizedInputKeySz_Rejected(t *testing.T) {
	ikm := []byte("short")
	out := make([]byte, 32)
	if ret := Wc_HKDF(WC_SHA256, ikm, 1<<20, nil, 0, nil, 0, out, len(out)); ret == 0 {
		t.Fatal("expected error on inputKeySz > len(inputKey)")
	}
}
