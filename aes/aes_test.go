package aes

import (
	"bytes"
	"testing"
	"github.com/wolfssl/go-wolfssl/internal/types"
)

func TestSealOpen(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, types.WC_AES_GCM_NONCE_SIZE)
	plaintext := []byte("test message")

	// Test encryption
	ciphertext, err := Seal(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Test decryption
	decrypted, err := Open(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match original: got %x want %x",
			decrypted, plaintext)
	}
}

func TestInvalidKey(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	nonce := make([]byte, types.WC_AES_GCM_NONCE_SIZE)
	plaintext := []byte("test")

	if _, err := Seal(key, nonce, plaintext); err == nil {
		t.Error("Seal accepted invalid key size")
	}

	if _, err := Open(key, nonce, plaintext); err == nil {
		t.Error("Open accepted invalid key size")
	}
}

func TestInvalidNonce(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24) // Wrong size
	plaintext := []byte("test")

	if _, err := Seal(key, nonce, plaintext); err == nil {
		t.Error("Seal accepted invalid nonce size")
	}

	if _, err := Open(key, nonce, plaintext); err == nil {
		t.Error("Open accepted invalid nonce size")
	}
}
