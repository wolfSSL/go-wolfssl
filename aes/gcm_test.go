package aes

import (
    "bytes"
    "crypto/rand"
    "testing"
)

func TestGCM(t *testing.T) {
    // Test vectors from NIST SP 800-38D
    key := make([]byte, 16)
    nonce := make([]byte, 12)
    plaintext := []byte("hello world")
    aad := []byte("additional data")

    block, err := NewCipher(key)
    if err != nil {
        t.Fatal(err)
    }

    aead, err := NewGCM(block)
    if err != nil {
        t.Fatal(err)
    }

    ciphertext := aead.Seal(nil, nonce, plaintext, aad)
    decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
    if err != nil {
        t.Fatal(err)
    }

    if !bytes.Equal(plaintext, decrypted) {
        t.Errorf("decryption failed: got %x, want %x", decrypted, plaintext)
    }
}

func TestGCMRandom(t *testing.T) {
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        t.Fatal(err)
    }

    block, err := NewCipher(key)
    if err != nil {
        t.Fatal(err)
    }

    aead, err := NewGCM(block)
    if err != nil {
        t.Fatal(err)
    }

    nonce := make([]byte, aead.NonceSize())
    plaintext := make([]byte, 1024)
    if _, err := rand.Read(plaintext); err != nil {
        t.Fatal(err)
    }

    ciphertext := aead.Seal(nil, nonce, plaintext, nil)
    decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        t.Fatal(err)
    }

    if !bytes.Equal(plaintext, decrypted) {
        t.Error("decryption failed")
    }
}
