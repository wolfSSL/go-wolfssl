/* aes-encrypt_test.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"bytes"
	"strings"
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

var testPassword = []byte("correct horse battery staple")

func newTestAes(t *testing.T) *wolfSSL.Aes {
	t.Helper()
	aes := wolfSSL.Wc_AesAllocAligned()
	if aes == nil {
		t.Fatal("Wc_AesAllocAligned failed")
	}
	if ret := wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		wolfSSL.Wc_AesFreeAllocAligned(aes)
		t.Fatalf("Wc_AesInit failed: %d", ret)
	}
	t.Cleanup(func() {
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)
	})
	return aes
}

func testPlaintext(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + 3)
	}
	return p
}

func mustSeal(t *testing.T, aes *wolfSSL.Aes, plaintext []byte, size int) []byte {
	t.Helper()
	sealed, err := sealData(aes, testPassword, plaintext, size)
	if err != nil {
		t.Fatalf("sealData failed: %v", err)
	}
	return sealed
}

func TestSealedFileRoundTrip(t *testing.T) {
	aes := newTestAes(t)
	sizes := []int{wolfSSL.AES_128_KEY_SIZE, wolfSSL.AES_192_KEY_SIZE, wolfSSL.AES_256_KEY_SIZE}
	for _, size := range sizes {
		for _, n := range []int{0, 1, 15, 16, 17, 1000} {
			plaintext := testPlaintext(n)
			sealed := mustSeal(t, aes, plaintext, size)
			if len(sealed) != HEADER_SIZE+n+TAG_SIZE {
				t.Fatalf("size %d len %d: sealed length %d", size, n, len(sealed))
			}
			if !bytes.HasPrefix(sealed, []byte(MAGIC)) {
				t.Fatalf("size %d len %d: missing format magic", size, n)
			}
			if n >= 16 && bytes.Contains(sealed, plaintext) {
				t.Fatalf("size %d len %d: plaintext visible in output", size, n)
			}
			opened, err := openData(aes, testPassword, sealed, size)
			if err != nil {
				t.Fatalf("size %d len %d: openData failed: %v", size, n, err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Fatalf("size %d len %d: round trip mismatch", size, n)
			}
		}
	}
}

func TestSealedFileUsesFreshSaltAndNonce(t *testing.T) {
	aes := newTestAes(t)
	plaintext := testPlaintext(32)
	a := mustSeal(t, aes, plaintext, wolfSSL.AES_256_KEY_SIZE)
	b := mustSeal(t, aes, plaintext, wolfSSL.AES_256_KEY_SIZE)
	if bytes.Equal(a[MAGIC_SIZE:HEADER_SIZE], b[MAGIC_SIZE:HEADER_SIZE]) {
		t.Fatal("two encryptions reused the same salt and nonce")
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions produced identical output")
	}
}

func TestSealedFileRejectsAnyModifiedByte(t *testing.T) {
	aes := newTestAes(t)
	sealed := mustSeal(t, aes, testPlaintext(20), wolfSSL.AES_256_KEY_SIZE)
	for i := range sealed {
		tampered := append([]byte(nil), sealed...)
		tampered[i] ^= 0x01
		opened, err := openData(aes, testPassword, tampered, wolfSSL.AES_256_KEY_SIZE)
		if err == nil || opened != nil {
			t.Fatalf("modified byte %d was accepted", i)
		}
		if i < MAGIC_SIZE && !strings.Contains(err.Error(), "Unsupported file format") {
			t.Fatalf("modified magic byte %d: unexpected error %v", i, err)
		}
		if i >= MAGIC_SIZE && !strings.Contains(err.Error(), "Authentication failed") {
			t.Fatalf("modified byte %d: unexpected error %v", i, err)
		}
	}
}

func TestSealedFileRejectsWrongPassword(t *testing.T) {
	aes := newTestAes(t)
	sealed := mustSeal(t, aes, testPlaintext(64), wolfSSL.AES_256_KEY_SIZE)
	for _, pw := range [][]byte{[]byte("wrong"), {}, append(append([]byte(nil), testPassword...), 'x')} {
		opened, err := openData(aes, pw, sealed, wolfSSL.AES_256_KEY_SIZE)
		if err == nil || opened != nil {
			t.Fatalf("wrong password %q was accepted", pw)
		}
	}
}

func TestSealedFileRejectsWrongKeySize(t *testing.T) {
	aes := newTestAes(t)
	sealed := mustSeal(t, aes, testPlaintext(64), wolfSSL.AES_256_KEY_SIZE)
	for _, size := range []int{wolfSSL.AES_128_KEY_SIZE, wolfSSL.AES_192_KEY_SIZE} {
		opened, err := openData(aes, testPassword, sealed, size)
		if err == nil || opened != nil {
			t.Fatalf("key size %d accepted a file sealed with a 256-bit key", size)
		}
	}
}

func TestSealedFileRejectsTruncation(t *testing.T) {
	aes := newTestAes(t)
	sealed := mustSeal(t, aes, testPlaintext(40), wolfSSL.AES_256_KEY_SIZE)
	for n := 0; n < len(sealed); n++ {
		opened, err := openData(aes, testPassword, sealed[:n], wolfSSL.AES_256_KEY_SIZE)
		if err == nil || opened != nil {
			t.Fatalf("file truncated to %d bytes was accepted", n)
		}
	}
	extended := append(append([]byte(nil), sealed...), 0)
	if opened, err := openData(aes, testPassword, extended, wolfSSL.AES_256_KEY_SIZE); err == nil || opened != nil {
		t.Fatal("file with an appended byte was accepted")
	}
}

func TestSealedFileRejectsUnversionedLayout(t *testing.T) {
	aes := newTestAes(t)
	/* salt(8) | iv(16) | ciphertext(32): the unauthenticated layout this example used to write */
	legacy := testPlaintext(8 + 16 + 32)
	opened, err := openData(aes, testPassword, legacy, wolfSSL.AES_256_KEY_SIZE)
	if err == nil || opened != nil {
		t.Fatal("file without the format magic was accepted")
	}
	if !strings.Contains(err.Error(), "Unsupported file format") {
		t.Fatalf("unexpected error %v", err)
	}
}
