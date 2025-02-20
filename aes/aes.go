package aes

import (
	"crypto/cipher"
	"errors"
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// NewGCM returns a new AES-GCM AEAD
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}

	// Create AES-GCM cipher
	block, err := wolfSSL.NewAESCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// Seal encrypts and authenticates plaintext, authenticates additional data,
// and returns the result. The nonce must be NonceSize() bytes long and unique
// for all time, for a given key.
func Seal(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != 24 {
		return nil, errors.New("invalid nonce size")
	}

	// Create AES-GCM cipher
	block, err := wolfSSL.NewAESCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt and authenticate
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Open decrypts and authenticates ciphertext, authenticates additional data,
// and returns the resulting plaintext. The nonce must be NonceSize() bytes
// long and both it and the additional data must match the value passed to Seal.
func Open(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != 24 {
		return nil, errors.New("invalid nonce size")
	}

	// Create AES-GCM cipher
	block, err := wolfSSL.NewAESCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
