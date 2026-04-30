/* correctness_test.go — differential tests asserting crypto invariants
 * (different inputs/keys must produce different outputs).
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

// Different inputs must produce different SHA-256 digests.
func TestSha256_DifferentInputs_DifferentDigests(t *testing.T) {
	a := make([]byte, WC_SHA256_DIGEST_SIZE)
	b := make([]byte, WC_SHA256_DIGEST_SIZE)
	ret := Wc_Sha256Hash([]byte("hello"), 5, a)
	skipIfNotCompiledIn(t, ret, "SHA-256")
	if ret != 0 {
		t.Fatalf("Sha256 a: %d", ret)
	}
	if ret := Wc_Sha256Hash([]byte("world"), 5, b); ret != 0 {
		t.Fatalf("Sha256 b: %d", ret)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different inputs produced identical digests")
	}
}

// HMAC must be key-dependent: same message + different key = different MAC.
func TestHmac_KeyDependent(t *testing.T) {
	msg := []byte("same message")
	mac1 := hmacOneShot(t, WC_SHA256, []byte("key-A"), msg, WC_SHA256_DIGEST_SIZE)
	mac2 := hmacOneShot(t, WC_SHA256, []byte("key-B"), msg, WC_SHA256_DIGEST_SIZE)
	if bytes.Equal(mac1, mac2) {
		t.Fatal("different keys produced identical MACs (HMAC is supposed to be keyed)")
	}
}

// HMAC must be message-dependent: same key + different message = different MAC.
func TestHmac_MessageDependent(t *testing.T) {
	key := []byte("the-key")
	mac1 := hmacOneShot(t, WC_SHA256, key, []byte("message-A"), WC_SHA256_DIGEST_SIZE)
	mac2 := hmacOneShot(t, WC_SHA256, key, []byte("message-B"), WC_SHA256_DIGEST_SIZE)
	if bytes.Equal(mac1, mac2) {
		t.Fatal("different messages produced identical MACs")
	}
}

// HKDF must produce different output for different inputs across all 3 params.
func TestHKDF_Differential(t *testing.T) {
	first := true
	out := func(ikm, salt, info []byte) []byte {
		o := make([]byte, 32)
		ret := Wc_HKDF(WC_SHA256, ikm, len(ikm), salt, len(salt), info, len(info), o, 32)
		if first {
			skipIfNotCompiledIn(t, ret, "HKDF")
			first = false
		}
		if ret != 0 {
			t.Fatalf("HKDF: %d", ret)
		}
		return o
	}
	base := out([]byte("ikm"), []byte("salt"), []byte("info"))
	if bytes.Equal(base, out([]byte("IKM"), []byte("salt"), []byte("info"))) {
		t.Fatal("HKDF: different IKM should give different output")
	}
	if bytes.Equal(base, out([]byte("ikm"), []byte("SALT"), []byte("info"))) {
		t.Fatal("HKDF: different salt should give different output")
	}
	if bytes.Equal(base, out([]byte("ikm"), []byte("salt"), []byte("INFO"))) {
		t.Fatal("HKDF: different info should give different output")
	}
}

// PBKDF2 differential across password/salt/iterations.
func TestPBKDF2_Differential(t *testing.T) {
	first := true
	derive := func(pwd, salt []byte, iter int) []byte {
		o := make([]byte, 32)
		ret := Wc_PBKDF2(o, pwd, len(pwd), salt, len(salt), iter, 32, WC_SHA256)
		if first {
			skipIfNotCompiledIn(t, ret, "PBKDF2")
			first = false
		}
		if ret != 0 {
			t.Fatalf("PBKDF2: %d", ret)
		}
		return o
	}
	base := derive([]byte("pwd"), []byte("salt-16-bytes!!!"), 1000)
	if bytes.Equal(base, derive([]byte("PWD"), []byte("salt-16-bytes!!!"), 1000)) {
		t.Fatal("PBKDF2: different password should give different key")
	}
	if bytes.Equal(base, derive([]byte("pwd"), []byte("SALT-16-bytes!!!"), 1000)) {
		t.Fatal("PBKDF2: different salt should give different key")
	}
	if bytes.Equal(base, derive([]byte("pwd"), []byte("salt-16-bytes!!!"), 2000)) {
		t.Fatal("PBKDF2: different iterations should give different key")
	}
}

// AES-CBC must produce different ciphertext for different keys.
func TestAesCbc_KeyDependent(t *testing.T) {
	first := true
	encrypt := func(key []byte) []byte {
		aes := allocAes(t)
		iv := bytes.Repeat([]byte{0x01}, AES_IV_SIZE)
		if ret := Wc_AesSetKey(aes, key, AES_256_KEY_SIZE, iv, AES_ENCRYPTION); ret != 0 {
			t.Fatalf("AesSetKey: %d", ret)
		}
		plain := bytes.Repeat([]byte("X"), 32)
		out := make([]byte, 32)
		ret := Wc_AesCbcEncrypt(aes, out, plain, 32)
		if first {
			skipIfNotCompiledIn(t, ret, "AES-CBC")
			first = false
		}
		if ret != 0 {
			t.Fatalf("AesCbcEncrypt: %d", ret)
		}
		return out
	}
	a := encrypt(bytes.Repeat([]byte{0xaa}, AES_256_KEY_SIZE))
	b := encrypt(bytes.Repeat([]byte{0xbb}, AES_256_KEY_SIZE))
	if bytes.Equal(a, b) {
		t.Fatal("AES-CBC: different keys produced identical ciphertext")
	}
}

// AES-CBC must produce different ciphertext for different IVs (with same key).
func TestAesCbc_IVDependent(t *testing.T) {
	first := true
	encrypt := func(iv []byte) []byte {
		aes := allocAes(t)
		key := bytes.Repeat([]byte{0xcc}, AES_256_KEY_SIZE)
		if ret := Wc_AesSetKey(aes, key, AES_256_KEY_SIZE, iv, AES_ENCRYPTION); ret != 0 {
			t.Fatalf("AesSetKey: %d", ret)
		}
		plain := bytes.Repeat([]byte("Y"), 32)
		out := make([]byte, 32)
		ret := Wc_AesCbcEncrypt(aes, out, plain, 32)
		if first {
			skipIfNotCompiledIn(t, ret, "AES-CBC")
			first = false
		}
		if ret != 0 {
			t.Fatalf("AesCbcEncrypt: %d", ret)
		}
		return out
	}
	a := encrypt(bytes.Repeat([]byte{0x01}, AES_IV_SIZE))
	b := encrypt(bytes.Repeat([]byte{0x02}, AES_IV_SIZE))
	if bytes.Equal(a, b) {
		t.Fatal("AES-CBC: different IVs produced identical ciphertext")
	}
}

// AES-GCM with wrong key must fail authentication.
func TestAesGcm_WrongKey_FailsAuth(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x11}, AES_256_KEY_SIZE)
	keyB := bytes.Repeat([]byte{0x22}, AES_256_KEY_SIZE)
	iv := bytes.Repeat([]byte{0x33}, AES_IV_SIZE)
	plain := []byte("auth-bound message")

	encAes := allocAes(t)
	ret := Wc_AesGcmSetKey(encAes, keyA, AES_256_KEY_SIZE)
	skipIfNotCompiledIn(t, ret, "AES-GCM")
	if ret != 0 {
		t.Fatalf("SetKey A: %d", ret)
	}
	cipher := make([]byte, len(plain))
	tag := make([]byte, AES_BLOCK_SIZE)
	if ret := Wc_AesGcmEncrypt(encAes, cipher, plain, iv, tag, nil); ret != 0 {
		t.Fatalf("Encrypt A: %d", ret)
	}

	decAes := allocAes(t)
	if ret := Wc_AesGcmSetKey(decAes, keyB, AES_256_KEY_SIZE); ret != 0 {
		t.Fatalf("SetKey B: %d", ret)
	}
	out := make([]byte, len(plain))
	if ret := Wc_AesGcmDecrypt(decAes, out, cipher, iv, tag, nil); ret == 0 {
		t.Fatal("AES-GCM: decryption with wrong key should fail authentication")
	}
}

// AES-GCM with wrong IV must fail authentication.
func TestAesGcm_WrongIV_FailsAuth(t *testing.T) {
	aes := allocAes(t)
	key := bytes.Repeat([]byte{0x44}, AES_256_KEY_SIZE)
	ret := Wc_AesGcmSetKey(aes, key, AES_256_KEY_SIZE)
	skipIfNotCompiledIn(t, ret, "AES-GCM")
	if ret != 0 {
		t.Fatalf("SetKey: %d", ret)
	}
	plain := []byte("data")
	cipher := make([]byte, len(plain))
	tag := make([]byte, AES_BLOCK_SIZE)
	ivEnc := bytes.Repeat([]byte{0x55}, AES_IV_SIZE)
	if ret := Wc_AesGcmEncrypt(aes, cipher, plain, ivEnc, tag, nil); ret != 0 {
		t.Fatalf("Encrypt: %d", ret)
	}
	ivDec := bytes.Repeat([]byte{0x55}, AES_IV_SIZE)
	ivDec[0] ^= 0x01 // flip a single bit
	out := make([]byte, len(plain))
	if ret := Wc_AesGcmDecrypt(aes, out, cipher, ivDec, tag, nil); ret == 0 {
		t.Fatal("AES-GCM: decryption with wrong IV should fail authentication")
	}
}

// ChaCha20-Poly1305 with wrong key must fail authentication.
func TestChaCha20Poly1305_WrongKey_FailsAuth(t *testing.T) {
	_, iv := chachaKeyAndIV()
	keyA := bytes.Repeat([]byte{0x77}, CHACHA20_POLY1305_AEAD_KEYSIZE)
	keyB := bytes.Repeat([]byte{0x88}, CHACHA20_POLY1305_AEAD_KEYSIZE)
	plain := []byte("data")
	cipher := make([]byte, len(plain))
	tag := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
	ret := Wc_ChaCha20Poly1305_Encrypt(keyA, iv, nil, plain, cipher, tag)
	skipIfNotCompiledIn(t, ret, "ChaCha20-Poly1305")
	if ret != 0 {
		t.Fatalf("Encrypt: %d", ret)
	}
	out := make([]byte, len(plain))
	if ret := Wc_ChaCha20Poly1305_Decrypt(keyB, iv, nil, cipher, tag, out); ret == 0 {
		t.Fatal("ChaCha20Poly1305: wrong key should fail authentication")
	}
}

// Curve25519 ECDH: third-party key cannot derive the same shared secret.
func TestCurve25519_ECDH_ThirdPartyMismatch(t *testing.T) {
	alice := makeCurve25519Key(t)
	bob := makeCurve25519Key(t)
	eve := makeCurve25519Key(t)

	aliceBob := make([]byte, curve25519KeySize)
	aliceEve := make([]byte, curve25519KeySize)
	if ret := Wc_curve25519_shared_secret(alice, bob, aliceBob); ret != 0 {
		t.Fatalf("alice<->bob: %d", ret)
	}
	if ret := Wc_curve25519_shared_secret(alice, eve, aliceEve); ret != 0 {
		t.Fatalf("alice<->eve: %d", ret)
	}
	if bytes.Equal(aliceBob, aliceEve) {
		t.Fatal("Curve25519: shared secrets with different peers should differ")
	}
}

// ECC: signature from one key cannot be verified by another key.
func TestEcc_WrongKey_FailsVerify(t *testing.T) {
	keyA := makeEccKey(t)
	keyB := makeEccKey(t)
	rng := newRng(t)
	hash := bytes.Repeat([]byte{0x42}, WC_SHA256_DIGEST_SIZE)

	sig := make([]byte, ECC_MAX_SIG_SIZE)
	sigLen := ECC_MAX_SIG_SIZE
	if ret := Wc_ecc_sign_hash(hash, len(hash), sig, &sigLen, rng, keyA); ret != 0 {
		t.Fatalf("sign with keyA: %d", ret)
	}

	res := 0
	ret := Wc_ecc_verify_hash(sig[:sigLen], sigLen, hash, len(hash), &res, keyB)
	if ret == 0 && res == 1 {
		t.Fatal("ECC: signature verified under wrong key")
	}
}

// PBKDF2 output is non-zero (catches accidentally-no-op implementation).
func TestPBKDF2_OutputNonZero(t *testing.T) {
	out := make([]byte, 32)
	ret := Wc_PBKDF2(out, []byte("p"), 1, []byte("salt"), 4, 100, 32, WC_SHA256)
	skipIfNotCompiledIn(t, ret, "PBKDF2")
	if ret != 0 {
		t.Fatalf("PBKDF2: %d", ret)
	}
	if bytes.Equal(out, make([]byte, 32)) {
		t.Fatal("PBKDF2 output is all zeros")
	}
}

// SHA-256 output is non-zero for non-zero input.
func TestSha256_OutputNonZero(t *testing.T) {
	out := make([]byte, WC_SHA256_DIGEST_SIZE)
	ret := Wc_Sha256Hash([]byte("any non-empty"), 13, out)
	skipIfNotCompiledIn(t, ret, "SHA-256")
	if ret != 0 {
		t.Fatalf("Sha256: %d", ret)
	}
	if bytes.Equal(out, make([]byte, WC_SHA256_DIGEST_SIZE)) {
		t.Fatal("SHA-256 output is all zeros")
	}
}
