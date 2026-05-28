/* aes_test.go
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

// allocAes returns a heap-aligned Aes context with t.Cleanup registered.
func allocAes(t *testing.T) *Aes {
	t.Helper()
	aes := Wc_AesAllocAligned()
	if aes == nil {
		t.Skip("AES not compiled in (Wc_AesAllocAligned returned nil)")
	}
	ret := Wc_AesInit(aes, nil, INVALID_DEVID)
	if ret == notCompiledIn {
		Wc_AesFreeAllocAligned(aes)
		t.Skip("AES not compiled in")
	}
	if ret != 0 {
		Wc_AesFreeAllocAligned(aes)
		t.Fatalf("Wc_AesInit returned %d", ret)
	}
	t.Cleanup(func() {
		Wc_AesFree(aes)
		Wc_AesFreeAllocAligned(aes)
	})
	return aes
}

func TestAesCbc_RoundTrip(t *testing.T) {
	aes := allocAes(t)
	key := bytes.Repeat([]byte{0x10}, AES_256_KEY_SIZE)
	iv := bytes.Repeat([]byte{0x20}, AES_IV_SIZE)
	plaintext := bytes.Repeat([]byte("ABCD1234"), 4) // 32 bytes (block-aligned)

	if ret := Wc_AesSetKey(aes, key, AES_256_KEY_SIZE, iv, AES_ENCRYPTION); ret != 0 {
		t.Fatalf("AesSetKey enc: %d", ret)
	}
	cipher := make([]byte, len(plaintext))
	ret := Wc_AesCbcEncrypt(aes, cipher, plaintext, len(plaintext))
	skipIfNotCompiledIn(t, ret, "AES-CBC")
	if ret != 0 {
		t.Fatalf("AesCbcEncrypt: %d", ret)
	}
	if bytes.Equal(cipher, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	if ret := Wc_AesSetKey(aes, key, AES_256_KEY_SIZE, iv, AES_DECRYPTION); ret != 0 {
		t.Fatalf("AesSetKey dec: %d", ret)
	}
	decrypted := make([]byte, len(plaintext))
	if ret := Wc_AesCbcDecrypt(aes, decrypted, cipher, len(cipher)); ret != 0 {
		t.Fatalf("AesCbcDecrypt: %d", ret)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch:\n got: %x\n want: %x", decrypted, plaintext)
	}
}

// Boundary: oversized sz must not let wc read past Go slice.
func TestAesCbc_OversizedSz_Rejected(t *testing.T) {
	aes := allocAes(t)
	key := bytes.Repeat([]byte{0x33}, AES_256_KEY_SIZE)
	iv := bytes.Repeat([]byte{0x44}, AES_IV_SIZE)
	if ret := Wc_AesSetKey(aes, key, AES_256_KEY_SIZE, iv, AES_ENCRYPTION); ret != 0 {
		t.Fatalf("AesSetKey: %d", ret)
	}
	in := make([]byte, 16)
	out := make([]byte, 16)
	if ret := Wc_AesCbcEncrypt(aes, out, in, 1<<20); ret == 0 {
		t.Fatal("expected error for sz > len(in)")
	}
}

func TestAesGcm_RawWrapper_RoundTrip(t *testing.T) {
	aes := allocAes(t)
	key := bytes.Repeat([]byte{0x55}, AES_256_KEY_SIZE)
	iv := bytes.Repeat([]byte{0x66}, AES_IV_SIZE)
	plaintext := []byte("AES-GCM round trip via raw wrapper")
	aad := []byte("aad")

	ret := Wc_AesGcmSetKey(aes, key, AES_256_KEY_SIZE)
	skipIfNotCompiledIn(t, ret, "AES-GCM")
	if ret != 0 {
		t.Fatalf("AesGcmSetKey: %d", ret)
	}
	cipher := make([]byte, len(plaintext))
	tag := make([]byte, AES_BLOCK_SIZE)
	if ret := Wc_AesGcmEncrypt(aes, cipher, plaintext, iv, tag, aad); ret != 0 {
		t.Fatalf("AesGcmEncrypt: %d", ret)
	}

	decrypted := make([]byte, len(plaintext))
	if ret := Wc_AesGcmDecrypt(aes, decrypted, cipher, iv, tag, aad); ret != 0 {
		t.Fatalf("AesGcmDecrypt: %d", ret)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAesGcm_TamperedCipher_FailsAuth(t *testing.T) {
	aes := allocAes(t)
	key := bytes.Repeat([]byte{0x77}, AES_256_KEY_SIZE)
	iv := bytes.Repeat([]byte{0x88}, AES_IV_SIZE)
	plain := []byte("authenticate me")
	ret := Wc_AesGcmSetKey(aes, key, AES_256_KEY_SIZE)
	skipIfNotCompiledIn(t, ret, "AES-GCM")
	if ret != 0 {
		t.Fatalf("AesGcmSetKey: %d", ret)
	}
	cipher := make([]byte, len(plain))
	tag := make([]byte, AES_BLOCK_SIZE)
	if ret := Wc_AesGcmEncrypt(aes, cipher, plain, iv, tag, nil); ret != 0 {
		t.Fatalf("AesGcmEncrypt: %d", ret)
	}
	cipher[0] ^= 1
	out := make([]byte, len(plain))
	if ret := Wc_AesGcmDecrypt(aes, out, cipher, iv, tag, nil); ret == 0 {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

// Appended-tag short-cipher: must error, not panic on inCipher[len-N:].
func TestAesGcm_AppendedTagDecrypt_ShortCipher(t *testing.T) {
	aes := allocAes(t)
	key := bytes.Repeat([]byte{0x99}, AES_256_KEY_SIZE)
	iv := bytes.Repeat([]byte{0xaa}, AES_IV_SIZE)
	ret := Wc_AesGcmSetKey(aes, key, AES_256_KEY_SIZE)
	skipIfNotCompiledIn(t, ret, "AES-GCM")
	if ret != 0 {
		t.Fatalf("AesGcmSetKey: %d", ret)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("short cipher should error, not panic: %v", r)
		}
	}()
	out := make([]byte, 16)
	if ret := Wc_AesGcm_Appended_Tag_Decrypt(aes, out, []byte{1, 2, 3}, iv, nil); ret == 0 {
		t.Fatal("expected error for cipher shorter than AES_BLOCK_SIZE")
	}
}

// PBKDF2 with separate password/output buffers must be deterministic.
func TestPBKDF2_DerivesDeterministicKey(t *testing.T) {
	password := []byte("password123")
	salt := []byte("saltsaltsaltsalt")
	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	ret := Wc_PBKDF2(out1, password, len(password), salt, len(salt), 1000, len(out1), WC_SHA256)
	skipIfNotCompiledIn(t, ret, "PBKDF2")
	if ret != 0 {
		t.Fatalf("Wc_PBKDF2 first call: %d", ret)
	}
	if ret := Wc_PBKDF2(out2, password, len(password), salt, len(salt), 1000, len(out2), WC_SHA256); ret != 0 {
		t.Fatalf("Wc_PBKDF2 second call: %d", ret)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("PBKDF2 not deterministic")
	}
	if bytes.Equal(out1, make([]byte, 32)) {
		t.Fatal("PBKDF2 output is all zeros")
	}
}

// Empty plaintext: wolfSSL accepts (tag-only) or rejects with BAD_FUNC_ARG
// depending on build options; both are valid contract-wise.
func TestAesGcm_EmptyPlaintext_MatchesWcBehavior(t *testing.T) {
	aes := allocAes(t)
	key := bytes.Repeat([]byte{0xab}, AES_256_KEY_SIZE)
	iv := bytes.Repeat([]byte{0xcd}, AES_IV_SIZE)
	ret := Wc_AesGcmSetKey(aes, key, AES_256_KEY_SIZE)
	skipIfNotCompiledIn(t, ret, "AES-GCM")
	if ret != 0 {
		t.Fatalf("AesGcmSetKey: %d", ret)
	}
	tag := make([]byte, AES_BLOCK_SIZE)
	got := Wc_AesGcmEncrypt(aes, []byte{}, []byte{}, iv, tag, nil)
	if got == notCompiledIn {
		t.Skip("AES-GCM empty-plaintext path not compiled in")
	}
	if got != 0 && got != BAD_FUNC_ARG {
		t.Fatalf("empty plaintext: want 0 or BAD_FUNC_ARG, got %d", got)
	}
}

// Boundary: kLen > len(out) must error.
func TestPBKDF2_OversizedKLen_Rejected(t *testing.T) {
	out := make([]byte, 16)
	if ret := Wc_PBKDF2(out, []byte("p"), 1, []byte("s"), 1, 1, 1<<20, WC_SHA256); ret == 0 {
		t.Fatal("expected error for kLen > len(out)")
	}
}
