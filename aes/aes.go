package aes

import (
	"errors"
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// NewGCM returns a new AES-GCM AEAD
func NewGCM(key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid key size")
	}

	// TODO: Implement AES-GCM using wolfSSL C bindings
	return nil
}

// Seal encrypts and authenticates plaintext, authenticates additional data,
// and returns the result. The nonce must be NonceSize() bytes long and unique
// for all time, for a given key.
func Seal(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != types.WC_AES_GCM_NONCE_SIZE {
		return nil, errors.New("invalid nonce size")
	}

	// Create AES-GCM cipher
	ciphertext := make([]byte, len(plaintext)+types.WC_AES_GCM_AUTH_SZ)
	// TODO: Implement encryption using wolfSSL C bindings
	
	return ciphertext, nil
}

// Open decrypts and authenticates ciphertext, authenticates additional data,
// and returns the resulting plaintext. The nonce must be NonceSize() bytes
// long and both it and the additional data must match the value passed to Seal.
func Open(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != types.WC_AES_GCM_NONCE_SIZE {
		return nil, errors.New("invalid nonce size")
	}
	if len(ciphertext) < types.WC_AES_GCM_AUTH_SZ {
		return nil, errors.New("ciphertext too short")
	}

	// Create AES-GCM cipher
	plaintext := make([]byte, len(ciphertext)-types.WC_AES_GCM_AUTH_SZ)
	// TODO: Implement decryption using wolfSSL C bindings

	return plaintext, nil
}
