/* curve25519_test.go
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

const curve25519KeySize = 32

func makeCurve25519Key(t *testing.T) *Curve25519_key {
	t.Helper()
	var key Curve25519_key
	ret := Wc_curve25519_init(&key)
	if ret == -174 {
		t.Skip("curve25519 not compiled in")
	}
	if ret != 0 {
		t.Fatalf("Wc_curve25519_init: %d", ret)
	}
	t.Cleanup(func() { Wc_curve25519_free(&key) })

	rng := newRng(t)
	if ret := Wc_curve25519_make_key(rng, curve25519KeySize, &key); ret != 0 {
		t.Fatalf("Wc_curve25519_make_key: %d", ret)
	}
	return &key
}

// Both peers should derive the same shared secret (X25519 ECDH).
func TestCurve25519_ECDH_AgreedSecret(t *testing.T) {
	alice := makeCurve25519Key(t)
	bob := makeCurve25519Key(t)

	aliceSecret := make([]byte, curve25519KeySize)
	bobSecret := make([]byte, curve25519KeySize)

	if ret := Wc_curve25519_shared_secret(alice, bob, aliceSecret); ret != 0 {
		t.Fatalf("alice shared_secret: %d", ret)
	}
	if ret := Wc_curve25519_shared_secret(bob, alice, bobSecret); ret != 0 {
		t.Fatalf("bob shared_secret: %d", ret)
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatalf("shared secrets differ:\n alice: %x\n bob:   %x", aliceSecret, bobSecret)
	}
	if bytes.Equal(aliceSecret, make([]byte, curve25519KeySize)) {
		t.Fatal("shared secret is all zeros")
	}
}
