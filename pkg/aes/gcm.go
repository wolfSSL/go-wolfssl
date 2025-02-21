// Package aes provides AES encryption using wolfSSL
package aes

import (
    "crypto/cipher"
    "errors"
    "github.com/wolfssl/go-wolfssl/pkg/cgo"
)

// gcm represents an AES-GCM cipher
type gcm struct {
    aes *cgo.Aes
}

// NewGCM returns a new AES-GCM cipher
func NewGCM(aes *cgo.Aes) (cipher.AEAD, error) {
    return &gcm{aes: aes}, nil
}

// NonceSize returns the size of the nonce used with this instance
func (g *gcm) NonceSize() int {
    return 12 // Standard GCM nonce size
}

// Overhead returns the maximum difference between plaintext and ciphertext lengths
func (g *gcm) Overhead() int {
    return 16 // Standard GCM tag size
}

// Seal encrypts and authenticates plaintext, authenticates additional data,
// and appends the result to dst, returning the updated slice.
func (g *gcm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
    if len(nonce) != g.NonceSize() {
        panic("wolfssl/aes: incorrect nonce length")
    }

    // Allocate space for ciphertext + tag
    ret := make([]byte, len(plaintext)+g.Overhead())
    if dst != nil {
        ret = append(dst, ret...)
    }

    // Encrypt and authenticate
    err := g.aes.GCMEncrypt(nonce, plaintext, additionalData, ret)
    if err != nil {
        panic("wolfssl/aes: " + err.Error())
    }

    return ret
}

// Open decrypts and authenticates ciphertext, authenticates additional data,
// and appends the result to dst, returning the updated slice.
func (g *gcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
    if len(nonce) != g.NonceSize() {
        return nil, errors.New("wolfssl/aes: incorrect nonce length")
    }
    if len(ciphertext) < g.Overhead() {
        return nil, errors.New("wolfssl/aes: ciphertext too short")
    }

    // Allocate space for plaintext
    ret := make([]byte, len(ciphertext)-g.Overhead())
    if dst != nil {
        ret = append(dst, ret...)
    }

    // Decrypt and verify
    err := g.aes.GCMDecrypt(nonce, ciphertext, additionalData, ret)
    if err != nil {
        return nil, errors.New("wolfssl/aes: authentication failed")
    }

    return ret, nil
}
