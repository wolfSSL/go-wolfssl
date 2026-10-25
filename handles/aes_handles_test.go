/* aes_handles_test.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

package handles

import (
	"bytes"
	"crypto/cipher"
	"strings"
	"sync"
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// Verify AesGcmAEAD satisfies cipher.AEAD at compile time.
var _ cipher.AEAD = (*AesGcmAEAD)(nil)

func TestAesGcmAEAD_NonceAndOverhead(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	a := NewAesGcmAEAD(key)

	if a.NonceSize() != wolfSSL.GCM_NONCE_MID_SZ {
		t.Fatalf("NonceSize() = %d, want %d", a.NonceSize(), wolfSSL.GCM_NONCE_MID_SZ)
	}
	if a.Overhead() != wolfSSL.AES_BLOCK_SIZE {
		t.Fatalf("Overhead() = %d, want %d", a.Overhead(), wolfSSL.AES_BLOCK_SIZE)
	}
}

func TestAesGcmAEAD_SealOpen_RoundTrip(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	for i := range key {
		key[i] = byte(i)
	}
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}

	plaintext := []byte("Hello, wolfCrypt AES-GCM AEAD!")

	ciphertext := a.Seal(nil, nonce, plaintext, nil)

	// ciphertext should be len(plaintext) + Overhead
	expectedLen := len(plaintext) + a.Overhead()
	if len(ciphertext) != expectedLen {
		t.Fatalf("Seal: ciphertext len = %d, want %d", len(ciphertext), expectedLen)
	}

	// ciphertext should differ from plaintext
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Fatal("Seal: ciphertext matches plaintext (encryption did nothing)")
	}

	decrypted, err := a.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Open: got %q, want %q", decrypted, plaintext)
	}
}

func TestAesGcmAEAD_SealOpen_WithAAD(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	plaintext := []byte("authenticated additional data test")
	aad := []byte("this is additional data")

	ciphertext := a.Seal(nil, nonce, plaintext, aad)

	// Decrypt with correct AAD
	decrypted, err := a.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open with correct AAD: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Open: got %q, want %q", decrypted, plaintext)
	}

	// Decrypt with wrong AAD should fail
	_, err = a.Open(nil, nonce, ciphertext, []byte("wrong aad"))
	if err == nil {
		t.Fatal("Open with wrong AAD should have failed")
	}
}

func TestAesGcmAEAD_SealOpen_EmptyPlaintext(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	key[0] = 0x42
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	plaintext := []byte{}

	ciphertext := a.Seal(nil, nonce, plaintext, nil)
	if len(ciphertext) != a.Overhead() {
		t.Fatalf("Seal empty: ciphertext len = %d, want %d (tag only)", len(ciphertext), a.Overhead())
	}

	decrypted, err := a.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("Open empty: got %d bytes, want 0", len(decrypted))
	}
}

func TestAesGcmAEAD_DstAppend(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	key[1] = 0xFF
	a := NewAesGcmAEAD(key)

	nonce := make([]byte, a.NonceSize())
	plaintext := []byte("dst append test")

	// Seal with non-nil dst prefix
	prefix := []byte("PREFIX:")
	ciphertext := a.Seal(prefix, nonce, plaintext, nil)
	if !bytes.HasPrefix(ciphertext, prefix) {
		t.Fatal("Seal: result should start with dst prefix")
	}

	// Strip prefix, Open with non-nil dst prefix
	ct := ciphertext[len(prefix):]
	outPrefix := []byte("OUT:")
	decrypted, err := a.Open(outPrefix, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.HasPrefix(decrypted, outPrefix) {
		t.Fatal("Open: result should start with dst prefix")
	}
	if !bytes.Equal(decrypted[len(outPrefix):], plaintext) {
		t.Fatalf("Open: got %q, want %q", decrypted[len(outPrefix):], plaintext)
	}
}

func TestAesGcmAEADOpenFailureWipesPlaintext(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	key[2] = 0x5a
	a := NewAesGcmAEAD(key)
	nonce := make([]byte, a.NonceSize())
	plaintext := []byte("plaintext that must not linger after a failed Open")
	ciphertext := a.Seal(nil, nonce, plaintext, nil)
	ciphertext[len(ciphertext)-1] ^= 0x01

	wiped := recordZeroBytes(t)
	if _, err := a.Open(nil, nonce, ciphertext, nil); err == nil {
		t.Fatal("Open accepted a tampered tag")
	}
	for _, b := range wiped() {
		if len(b) == len(plaintext) && allZero(b) {
			return
		}
	}
	t.Fatal("decrypt output buffer was not wiped after authentication failure")
}

func TestAesGcmAEADZeroWipesKey(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	a := NewAesGcmAEAD(key)
	nonce := make([]byte, a.NonceSize())
	ciphertext := a.Seal(nil, nonce, []byte("data"), nil)

	a.Zero()
	if !allZero(a.st.key[:]) {
		t.Fatal("Zero left key bytes in the AEAD")
	}
	if _, err := a.Open(nil, nonce, ciphertext, nil); err == nil {
		t.Fatal("Open succeeded after Zero")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Seal did not panic after Zero")
		}
	}()
	a.Seal(nil, nonce, []byte("data"), nil)
}

func TestAesGcmAEADZeroReachesCopies(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	key[0] = 0x11
	a := NewAesGcmAEAD(key)
	b := *a
	a.Zero()
	defer func() {
		if recover() == nil {
			t.Fatal("copy of a zeroed AEAD could still Seal")
		}
	}()
	b.Seal(nil, make([]byte, b.NonceSize()), []byte("data"), nil)
}

func TestAesGcmAEADZeroConcurrentWithUse(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	for i := range key {
		key[i] = byte(0x80 + i)
	}
	a := NewAesGcmAEAD(key)
	zeroKeyAEAD := NewAesGcmAEAD([wolfSSL.AES_256_KEY_SIZE]byte{})
	nonce := make([]byte, a.NonceSize())
	msg := []byte("concurrent zero")
	ct0 := a.Seal(nil, nonce, msg, nil)
	var ready, wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		ready.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			signalled := false
			defer func() {
				if !signalled {
					ready.Done()
				}
				if r := recover(); r != nil {
					if s, ok := r.(string); !ok || !strings.Contains(s, "after Zero") {
						t.Errorf("unexpected panic: %v", r)
					}
				}
			}()
			for j := 0; j < 50; j++ {
				ct := a.Seal(nil, nonce, msg, nil)
				if _, err := zeroKeyAEAD.Open(nil, nonce, ct, nil); err == nil {
					t.Error("Seal used a wiped key")
				}
				_, _ = a.Open(nil, nonce, ct, nil)
				if !signalled {
					signalled = true
					ready.Done()
				}
			}
		}()
	}
	ready.Wait()
	a.Zero()
	wg.Wait()
	if _, err := a.Open(nil, nonce, ct0, nil); err == nil {
		t.Fatal("Open succeeded after Zero")
	}
}

func TestAesGcmAEADZeroWaitsForInFlightSeal(t *testing.T) {
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	a := NewAesGcmAEAD(key)
	nonce := make([]byte, a.NonceSize())
	msg := []byte("in flight")

	entered, release := holdFirstAcquire(t)
	sealed := make(chan []byte, 1)
	go func() { sealed <- a.Seal(nil, nonce, msg, nil) }()
	<-entered
	zeroed := make(chan struct{})
	go func() {
		a.Zero()
		close(zeroed)
	}()
	assertBlocked(t, zeroed, release, "Zero")
	ct := <-sealed
	pt, err := NewAesGcmAEAD(key).Open(nil, nonce, ct, nil)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("in-flight Seal did not use the original key: %v", err)
	}
	if _, err := a.Open(nil, nonce, ct, nil); err == nil {
		t.Fatal("Open succeeded after Zero")
	}
}
