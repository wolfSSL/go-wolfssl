package aes

import (
	"errors"
	"fmt"
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// #cgo CFLAGS: -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
/*
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
*/
import "C"

// Seal encrypts and authenticates plaintext using AES-GCM.
// The nonce must be NonceSize() bytes long and unique for all time, for a given key.
func Seal(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != types.WC_AES_GCM_NONCE_SIZE {
		return nil, errors.New("invalid nonce size")
	}

	// Create AES-GCM cipher
	aes := C.Aes{}
	if ret := C.wc_AesInit(&aes, nil, -1); ret != 0 {
		return nil, fmt.Errorf("failed to initialize AES: %d", ret)
	}
	defer C.wc_AesFree(&aes)

	// Set key
	if ret := C.wc_AesGcmSetKey(&aes, (*C.byte)(&key[0]), C.word32(len(key))); ret != 0 {
		return nil, fmt.Errorf("failed to set key: %d", ret)
	}

	// Encrypt and authenticate
	ciphertext := make([]byte, len(plaintext)+types.WC_AES_GCM_AUTH_SZ)
	if ret := C.wc_AesGcmEncrypt(&aes, (*C.byte)(&ciphertext[0]), (*C.byte)(&plaintext[0]),
		C.word32(len(plaintext)), (*C.byte)(&nonce[0]), C.word32(len(nonce)),
		(*C.byte)(&ciphertext[len(plaintext)]), C.word32(types.WC_AES_GCM_AUTH_SZ),
		nil, 0); ret != 0 {
		return nil, fmt.Errorf("encryption failed: %d", ret)
	}

	return ciphertext, nil
}

// Open decrypts and authenticates ciphertext using AES-GCM.
// The nonce must be NonceSize() bytes long and match the value passed to Seal.
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
	aes := C.Aes{}
	if ret := C.wc_AesInit(&aes, nil, -1); ret != 0 {
		return nil, fmt.Errorf("failed to initialize AES: %d", ret)
	}
	defer C.wc_AesFree(&aes)

	// Set key
	if ret := C.wc_AesGcmSetKey(&aes, (*C.byte)(&key[0]), C.word32(len(key))); ret != 0 {
		return nil, fmt.Errorf("failed to set key: %d", ret)
	}

	// Decrypt and verify
	plaintext := make([]byte, len(ciphertext)-types.WC_AES_GCM_AUTH_SZ)
	if ret := C.wc_AesGcmDecrypt(&aes, (*C.byte)(&plaintext[0]), (*C.byte)(&ciphertext[0]),
		C.word32(len(ciphertext)-types.WC_AES_GCM_AUTH_SZ), (*C.byte)(&nonce[0]),
		C.word32(len(nonce)), (*C.byte)(&ciphertext[len(plaintext)]),
		C.word32(types.WC_AES_GCM_AUTH_SZ), nil, 0); ret != 0 {
		return nil, fmt.Errorf("decryption failed: %d", ret)
	}

	return plaintext, nil
}
