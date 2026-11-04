/* boundary_test.go — wrappers must reject empty/oversized slice arguments
 * with a Go error rather than panic, since wc can't see Go slice lengths.
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
	"testing"
)

// assertNoPanic runs fn and fails the test if fn panics.
func assertNoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: panicked instead of returning error: %v", name, r)
		}
	}()
	fn()
}

// Every public wrapper must return an error on bad inputs, never panic.
func TestWrapperNilSliceGuards(t *testing.T) {
	t.Run("Sha256Hash_emptyOutput", func(t *testing.T) {
		var ret int
		assertNoPanic(t, "Wc_Sha256Hash", func() {
			ret = Wc_Sha256Hash([]byte("data"), 4, []byte{})
		})
		if ret == 0 {
			t.Fatal("empty output should error")
		}
	})

	t.Run("Sha256Hash_oversizedInputSz", func(t *testing.T) {
		var ret int
		assertNoPanic(t, "Wc_Sha256Hash", func() {
			ret = Wc_Sha256Hash([]byte{1}, 1<<20, make([]byte, WC_SHA256_DIGEST_SIZE))
		})
		if ret == 0 {
			t.Fatal("oversized inputSz should error")
		}
	})

	t.Run("HKDF_emptyOutput", func(t *testing.T) {
		var ret int
		assertNoPanic(t, "Wc_HKDF", func() {
			ret = Wc_HKDF(WC_SHA256, []byte("ikm"), 3, nil, 0, nil, 0, []byte{}, 0)
		})
		if ret == 0 {
			t.Fatal("empty output should error")
		}
	})

	t.Run("HKDF_oversizedOutSz", func(t *testing.T) {
		var ret int
		assertNoPanic(t, "Wc_HKDF", func() {
			ret = Wc_HKDF(WC_SHA256, []byte("ikm"), 3, nil, 0, nil, 0, make([]byte, 8), 1<<20)
		})
		if ret == 0 {
			t.Fatal("oversized outSz should error")
		}
	})

	t.Run("HmacSetKey_oversizedKeySz", func(t *testing.T) {
		hmac := Wc_HmacAllocAligned()
		if hmac == nil {
			t.Skip("HMAC not compiled in")
		}
		defer Wc_HmacFreeAllocAligned(hmac)
		switch ret := Wc_HmacInit(hmac, nil, INVALID_DEVID); ret {
		case 0:
		case notCompiledIn:
			t.Skip("HMAC not compiled in")
		default:
			t.Fatalf("Wc_HmacInit: %d", ret)
		}
		defer Wc_HmacFree(hmac)
		var ret int
		assertNoPanic(t, "Wc_HmacSetKey", func() {
			ret = Wc_HmacSetKey(hmac, WC_SHA256, []byte{1}, 1<<20)
		})
		if ret == 0 {
			t.Fatal("oversized keySz should error")
		}
	})

	t.Run("HmacFinal_emptyOut", func(t *testing.T) {
		hmac := Wc_HmacAllocAligned()
		if hmac == nil {
			t.Skip("HMAC not compiled in")
		}
		defer Wc_HmacFreeAllocAligned(hmac)
		switch ret := Wc_HmacInit(hmac, nil, INVALID_DEVID); ret {
		case 0:
		case notCompiledIn:
			t.Skip("HMAC not compiled in")
		default:
			t.Fatalf("Wc_HmacInit: %d", ret)
		}
		defer Wc_HmacFree(hmac)
		Wc_HmacSetKey(hmac, WC_SHA256, []byte("k"), 1)
		var ret int
		assertNoPanic(t, "Wc_HmacFinal", func() {
			ret = Wc_HmacFinal(hmac, []byte{})
		})
		if ret == 0 {
			t.Fatal("empty out should error")
		}
	})

	t.Run("AesCbcEncrypt_oversizedSz", func(t *testing.T) {
		aes := Wc_AesAllocAligned()
		if aes == nil {
			t.Skip("AES not compiled in")
		}
		defer Wc_AesFreeAllocAligned(aes)
		switch ret := Wc_AesInit(aes, nil, INVALID_DEVID); ret {
		case 0:
		case notCompiledIn:
			t.Skip("AES not compiled in")
		default:
			t.Fatalf("Wc_AesInit: %d", ret)
		}
		defer Wc_AesFree(aes)
		key := make([]byte, AES_256_KEY_SIZE)
		iv := make([]byte, AES_IV_SIZE)
		Wc_AesSetKey(aes, key, AES_256_KEY_SIZE, iv, AES_ENCRYPTION)
		in := make([]byte, 16)
		out := make([]byte, 16)
		var ret int
		assertNoPanic(t, "Wc_AesCbcEncrypt", func() {
			ret = Wc_AesCbcEncrypt(aes, out, in, 1<<20)
		})
		if ret == 0 {
			t.Fatal("oversized sz should error")
		}
	})

	t.Run("AesGcmAppendedTagDecrypt_shortCipher", func(t *testing.T) {
		aes := Wc_AesAllocAligned()
		if aes == nil {
			t.Skip("AES not compiled in")
		}
		defer Wc_AesFreeAllocAligned(aes)
		switch ret := Wc_AesInit(aes, nil, INVALID_DEVID); ret {
		case 0:
		case notCompiledIn:
			t.Skip("AES not compiled in")
		default:
			t.Fatalf("Wc_AesInit: %d", ret)
		}
		defer Wc_AesFree(aes)
		key := make([]byte, AES_256_KEY_SIZE)
		Wc_AesGcmSetKey(aes, key, AES_256_KEY_SIZE)
		var ret int
		assertNoPanic(t, "Wc_AesGcm_Appended_Tag_Decrypt", func() {
			ret = Wc_AesGcm_Appended_Tag_Decrypt(aes, make([]byte, 4), []byte{1, 2, 3}, make([]byte, AES_IV_SIZE), nil)
		})
		if ret == 0 {
			t.Fatal("short cipher should error")
		}
	})

	t.Run("ChaChaPoly1305_AppendedTagDecrypt_shortCipher", func(t *testing.T) {
		key := make([]byte, CHACHA20_POLY1305_AEAD_KEYSIZE)
		iv := make([]byte, CHACHA20_POLY1305_AEAD_IV_SIZE)
		var ret int
		assertNoPanic(t, "Wc_ChaCha20Poly1305_Appended_Tag_Decrypt", func() {
			ret = Wc_ChaCha20Poly1305_Appended_Tag_Decrypt(key, iv, nil, []byte{1, 2, 3}, make([]byte, 4))
		})
		if ret == 0 {
			t.Fatal("short cipher should error")
		}
	})

	t.Run("ConstantCompare_oversizedLength", func(t *testing.T) {
		// ConstantCompare returns 0 (mismatch) on bad length — separate test
		// asserts the value; here we verify no-panic only.
		assertNoPanic(t, "ConstantCompare", func() {
			ConstantCompare([]byte{1, 2}, []byte{1, 2}, 1<<20)
		})
	})

	t.Run("WolfSSL_X509_load_certificate_buffer_emptyBuff", func(t *testing.T) {
		// Returns *WOLFSSL_X509 (not int); empty buf must yield nil, not panic.
		var got *WOLFSSL_X509
		assertNoPanic(t, "WolfSSL_X509_load_certificate_buffer", func() {
			got = WolfSSL_X509_load_certificate_buffer([]byte{}, 0, SSL_FILETYPE_PEM)
		})
		if got != nil {
			t.Fatal("empty buffer should return nil")
		}
	})
}

// ConstantCompare must reject attacker-controlled oversized/negative lengths.
func TestConstantCompare_AttackerLength_ReturnsZero(t *testing.T) {
	a := []byte{0xaa, 0xbb}
	b := []byte{0xaa, 0xbb}
	if got := ConstantCompare(a, b, 999); got != 0 {
		t.Fatalf("oversized length should return 0 (not match), got %d", got)
	}
	if got := ConstantCompare(a, b, -1); got != 0 {
		t.Fatalf("negative length should return 0, got %d", got)
	}
	if got := ConstantCompare(a, b, 2); got != 1 {
		t.Fatalf("equal-length match should return 1, got %d", got)
	}
}
