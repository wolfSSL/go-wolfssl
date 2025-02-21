package aes

import (
    "bytes"
    "crypto/cipher"
    "testing"
)

func TestGCM(t *testing.T) {
    // Test vectors from NIST CAVP
    key := []byte{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    }
    nonce := []byte{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    }
    plaintext := []byte("Hello, world!")
    aad := []byte("Additional data")

    aead, err := NewGCM(key)
    if err != nil {
        t.Fatalf("NewGCM() failed: %v", err)
    }

    // Test encryption
    ciphertext := aead.Seal(nil, nonce, plaintext, aad)
    if len(ciphertext) != len(plaintext)+aead.Overhead() {
        t.Errorf("Seal() returned wrong length: got %d, want %d",
            len(ciphertext), len(plaintext)+aead.Overhead())
    }

    // Test decryption
    decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
    if err != nil {
        t.Fatalf("Open() failed: %v", err)
    }
    if !bytes.Equal(decrypted, plaintext) {
        t.Errorf("Open() returned wrong plaintext: got %x, want %x",
            decrypted, plaintext)
    }

    // Test that modifying ciphertext causes authentication failure
    ciphertext[0] ^= 0x01
    if _, err := aead.Open(nil, nonce, ciphertext, aad); err == nil {
        t.Error("Open() succeeded with modified ciphertext")
    }

    // Test that modifying AAD causes authentication failure
    aad[0] ^= 0x01
    if _, err := aead.Open(nil, nonce, ciphertext, aad); err == nil {
        t.Error("Open() succeeded with modified AAD")
    }

    // Test that the AEAD interface is properly implemented
    var _ cipher.AEAD = aead
}
