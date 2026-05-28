/* chacha_poly_test.go
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

func chachaKeyAndIV() (key, iv []byte) {
	key = make([]byte, CHACHA20_POLY1305_AEAD_KEYSIZE)
	for i := range key {
		key[i] = byte(i)
	}
	iv = make([]byte, CHACHA20_POLY1305_AEAD_IV_SIZE)
	for i := range iv {
		iv[i] = byte(i + 100)
	}
	return key, iv
}

func TestChaCha20Poly1305_RoundTrip(t *testing.T) {
	key, iv := chachaKeyAndIV()
	aad := []byte("authenticated additional data")
	plaintext := []byte("ChaCha20-Poly1305 round-trip test message")

	cipher := make([]byte, len(plaintext))
	tag := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)

	ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, aad, plaintext, cipher, tag)
	skipIfNotCompiledIn(t, ret, "ChaCha20-Poly1305")
	if ret != 0 {
		t.Fatalf("Encrypt returned %d", ret)
	}
	if bytes.Equal(cipher, plaintext) {
		t.Fatal("ciphertext equals plaintext (encryption did nothing)")
	}

	decrypted := make([]byte, len(plaintext))
	if ret := Wc_ChaCha20Poly1305_Decrypt(key, iv, aad, cipher, tag, decrypted); ret != 0 {
		t.Fatalf("Decrypt returned %d", ret)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch:\n got:  %q\n want: %q", decrypted, plaintext)
	}
}

// Empty plaintext: wolfSSL accepts (tag-only) or rejects with BAD_FUNC_ARG
// depending on build options; both are valid contract-wise.
func TestChaCha20Poly1305_EmptyPlaintext_MatchesWcBehavior(t *testing.T) {
	key, iv := chachaKeyAndIV()
	cipher := []byte{}
	tag := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
	ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, nil, []byte{}, cipher, tag)
	skipIfNotCompiledIn(t, ret, "ChaCha20-Poly1305")
	if ret != 0 && ret != BAD_FUNC_ARG {
		t.Fatalf("empty plaintext: want 0 or BAD_FUNC_ARG, got %d", ret)
	}
}

// Tampered ciphertext must fail Open (authenticity).
func TestChaCha20Poly1305_TamperedCiphertext_Fails(t *testing.T) {
	key, iv := chachaKeyAndIV()
	plaintext := []byte("important message")
	cipher := make([]byte, len(plaintext))
	tag := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)

	ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, nil, plaintext, cipher, tag)
	skipIfNotCompiledIn(t, ret, "ChaCha20-Poly1305")
	if ret != 0 {
		t.Fatalf("Encrypt: %d", ret)
	}

	// Flip a bit in the ciphertext.
	cipher[0] ^= 0x01

	decrypted := make([]byte, len(plaintext))
	if ret := Wc_ChaCha20Poly1305_Decrypt(key, iv, nil, cipher, tag, decrypted); ret == 0 {
		t.Fatal("decrypting tampered ciphertext should fail authentication")
	}
}

// Tampered tag must fail Open.
func TestChaCha20Poly1305_TamperedTag_Fails(t *testing.T) {
	key, iv := chachaKeyAndIV()
	plaintext := []byte("important message")
	cipher := make([]byte, len(plaintext))
	tag := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)

	ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, nil, plaintext, cipher, tag)
	skipIfNotCompiledIn(t, ret, "ChaCha20-Poly1305")
	if ret != 0 {
		t.Fatalf("Encrypt: %d", ret)
	}
	tag[0] ^= 0x01

	decrypted := make([]byte, len(plaintext))
	if ret := Wc_ChaCha20Poly1305_Decrypt(key, iv, nil, cipher, tag, decrypted); ret == 0 {
		t.Fatal("decrypting with tampered tag should fail authentication")
	}
}

// Wrong AAD must fail Open.
func TestChaCha20Poly1305_WrongAAD_Fails(t *testing.T) {
	key, iv := chachaKeyAndIV()
	plaintext := []byte("aad-bound message")
	cipher := make([]byte, len(plaintext))
	tag := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)

	ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, []byte("aad-A"), plaintext, cipher, tag)
	skipIfNotCompiledIn(t, ret, "ChaCha20-Poly1305")
	if ret != 0 {
		t.Fatalf("Encrypt: %d", ret)
	}
	decrypted := make([]byte, len(plaintext))
	if ret := Wc_ChaCha20Poly1305_Decrypt(key, iv, []byte("aad-B"), cipher, tag, decrypted); ret == 0 {
		t.Fatal("decrypting with wrong AAD should fail")
	}
}

// Short ciphertext (< tag size) for Appended_Tag_Decrypt must error, not panic.
func TestChaCha20Poly1305_AppendedTagDecrypt_ShortCipher(t *testing.T) {
	key, iv := chachaKeyAndIV()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("short cipher should error, not panic: %v", r)
		}
	}()
	out := make([]byte, 32)
	short := []byte{1, 2, 3} // shorter than AUTHTAG_SIZE (16)
	if ret := Wc_ChaCha20Poly1305_Appended_Tag_Decrypt(key, iv, nil, short, out); ret == 0 {
		t.Fatal("expected error on short ciphertext")
	}
}

func TestChaCha20Poly1305_AppendedTag_RoundTrip(t *testing.T) {
	key, iv := chachaKeyAndIV()
	plaintext := []byte("appended-tag message")

	out, ret := Wc_ChaCha20Poly1305_Appended_Tag_Encrypt(key, iv, nil, plaintext, nil)
	skipIfNotCompiledIn(t, ret, "ChaCha20-Poly1305")
	if ret != 0 {
		t.Fatalf("Appended_Tag_Encrypt: %d", ret)
	}
	if len(out) != len(plaintext)+CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE {
		t.Fatalf("output length %d, want %d", len(out), len(plaintext)+CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
	}

	decrypted := make([]byte, len(plaintext))
	if ret := Wc_ChaCha20Poly1305_Appended_Tag_Decrypt(key, iv, nil, out, decrypted); ret != 0 {
		t.Fatalf("Appended_Tag_Decrypt: %d", ret)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// XChaCha20-Poly1305 round-trip with non-empty plaintext.
func TestXChaCha20Poly1305_RoundTrip(t *testing.T) {
	key := make([]byte, CHACHA20_POLY1305_AEAD_KEYSIZE)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, XCHACHA20_POLY1305_AEAD_NONCE_SIZE)
	plaintext := []byte("XChaCha20-Poly1305 round-trip")
	cipher := make([]byte, len(plaintext)+CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
	ret := Wc_XChaCha20Poly1305_Encrypt(cipher, plaintext, nil, iv, key)
	skipIfNotCompiledIn(t, ret, "XChaCha20-Poly1305")
	if ret != 0 {
		t.Fatalf("Encrypt: %d", ret)
	}
	out := make([]byte, len(plaintext))
	if ret := Wc_XChaCha20Poly1305_Decrypt(out, cipher, nil, iv, key); ret != 0 {
		t.Fatalf("Decrypt: %d", ret)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", out, plaintext)
	}
}
