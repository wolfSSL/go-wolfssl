/* ecc_test.go
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

const eccP256KeySize = 32

func makeEccKey(t *testing.T) *Ecc_key {
	t.Helper()
	key := Wc_Ecc_AllocKey()
	if key == nil {
		t.Fatal("Wc_Ecc_AllocKey returned nil")
	}
	ret := Wc_ecc_init(key)
	if ret == notCompiledIn {
		Wc_Ecc_FreeKey(key)
		t.Skip("ECC not compiled in")
	}
	if ret != 0 {
		Wc_Ecc_FreeKey(key)
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	t.Cleanup(func() { Wc_Ecc_FreeKey(key) })

	rng := newRng(t)
	ret = Wc_ecc_make_key(rng, eccP256KeySize, key)
	if ret == notCompiledIn {
		t.Skip("ECC not compiled in")
	}
	if ret != 0 {
		t.Fatalf("Wc_ecc_make_key: %d", ret)
	}
	return key
}

func TestEcc_SignAndVerify_RoundTrip(t *testing.T) {
	key := makeEccKey(t)
	rng := newRng(t)

	hash := bytes.Repeat([]byte{0xab}, WC_SHA256_DIGEST_SIZE)
	sig := make([]byte, ECC_MAX_SIG_SIZE)
	sigLen := ECC_MAX_SIG_SIZE
	if ret := Wc_ecc_sign_hash(hash, len(hash), sig, &sigLen, rng, key); ret != 0 {
		t.Fatalf("Wc_ecc_sign_hash: %d", ret)
	}
	if sigLen <= 0 || sigLen > ECC_MAX_SIG_SIZE {
		t.Fatalf("sigLen %d out of range", sigLen)
	}

	res := 0
	if ret := Wc_ecc_verify_hash(sig[:sigLen], sigLen, hash, len(hash), &res, key); ret != 0 {
		t.Fatalf("Wc_ecc_verify_hash: %d", ret)
	}
	if res != 1 {
		t.Fatalf("verify result = %d, want 1 (valid)", res)
	}
}

// Tampered hash must fail verification.
func TestEcc_TamperedHash_FailsVerify(t *testing.T) {
	key := makeEccKey(t)
	rng := newRng(t)

	hash := bytes.Repeat([]byte{0xcd}, WC_SHA256_DIGEST_SIZE)
	sig := make([]byte, ECC_MAX_SIG_SIZE)
	sigLen := ECC_MAX_SIG_SIZE
	if ret := Wc_ecc_sign_hash(hash, len(hash), sig, &sigLen, rng, key); ret != 0 {
		t.Fatalf("Wc_ecc_sign_hash: %d", ret)
	}

	hash[0] ^= 0x01
	res := 0
	// Verify must report failure as either a non-zero ret OR res == 0.
	ret := Wc_ecc_verify_hash(sig[:sigLen], sigLen, hash, len(hash), &res, key)
	if ret == 0 && res == 1 {
		t.Fatal("tampered hash verified as valid")
	}
}

// Boundary: empty hash (which is meaningless for ECC sign) must error, not panic.
func TestEcc_SignHash_EmptyHash_NoPanic(t *testing.T) {
	key := makeEccKey(t)
	rng := newRng(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("empty hash should error, not panic: %v", r)
		}
	}()
	sig := make([]byte, ECC_MAX_SIG_SIZE)
	sigLen := ECC_MAX_SIG_SIZE
	if ret := Wc_ecc_sign_hash([]byte{}, 0, sig, &sigLen, rng, key); ret == 0 {
		t.Fatal("expected error for empty hash")
	}
}

// Boundary: nil outLen must error, not nil-deref panic.
func TestEcc_SignHash_NilOutLen_NoPanic(t *testing.T) {
	key := makeEccKey(t)
	rng := newRng(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil outLen should error, not panic: %v", r)
		}
	}()
	hash := bytes.Repeat([]byte{0xab}, WC_SHA256_DIGEST_SIZE)
	sig := make([]byte, ECC_MAX_SIG_SIZE)
	if ret := Wc_ecc_sign_hash(hash, len(hash), sig, nil, rng, key); ret == 0 {
		t.Fatal("expected error for nil outLen")
	}
}

// Wc_ecc_negate_private must actually change the private scalar.
func TestEcc_NegatePrivate(t *testing.T) {
	key := makeEccKey(t)

	before := make([]byte, eccP256KeySize)
	beforeLen := len(before)
	if ret := Wc_ecc_export_private_only(key, before, &beforeLen); ret != 0 {
		t.Fatalf("export pre-negate: %d", ret)
	}

	ret := Wc_ecc_negate_private(key)
	if ret == notCompiledIn {
		t.Skip("Wc_ecc_negate_private not compiled in (requires WOLFSSL_PUBLIC_MP)")
	}
	if ret != 0 {
		t.Fatalf("Wc_ecc_negate_private returned %d", ret)
	}

	after := make([]byte, eccP256KeySize)
	afterLen := len(after)
	if ret := Wc_ecc_export_private_only(key, after, &afterLen); ret != 0 {
		t.Fatalf("export post-negate: %d", ret)
	}
	if bytes.Equal(before[:beforeLen], after[:afterLen]) {
		t.Fatal("negate_private did not change the private scalar")
	}
}

// Round-trip via export/import_x963.
func TestEcc_ExportImportX963_RoundTrip(t *testing.T) {
	key := makeEccKey(t)

	pubBuf := make([]byte, 256)
	pubLen := len(pubBuf)
	if ret := Wc_ecc_export_x963_ex(key, pubBuf, &pubLen, 0); ret != 0 {
		t.Fatalf("Wc_ecc_export_x963_ex: %d", ret)
	}
	if pubLen <= 0 || pubLen > len(pubBuf) {
		t.Fatalf("pubLen %d out of range", pubLen)
	}

	imported := Wc_Ecc_AllocKey()
	if imported == nil {
		t.Fatal("Wc_Ecc_AllocKey returned nil")
	}
	defer Wc_Ecc_FreeKey(imported)
	if ret := Wc_ecc_init(imported); ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}

	if ret := Wc_ecc_import_x963_ex(pubBuf[:pubLen], pubLen, imported, ECC_SECP256R1); ret != 0 {
		t.Fatalf("Wc_ecc_import_x963_ex: %d", ret)
	}
}
