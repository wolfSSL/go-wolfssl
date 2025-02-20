package kdf

import (
	"crypto/hmac"
	"errors"
	"github.com/wolfssl/go-wolfssl/internal/types"
	"github.com/wolfssl/go-wolfssl/sha256"
)

// HKDF performs HMAC-based Key Derivation Function using SHA256
func HKDF(secret, salt, info []byte, outLen int) ([]byte, error) {
	// Extract phase
	if salt == nil {
		salt = make([]byte, types.WC_SHA256_DIGEST_SIZE)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)

	// Expand phase
	output := make([]byte, 0, outLen)
	counter := byte(1)
	prev := []byte{}

	for len(output) < outLen {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		output = append(output, prev...)
		counter++
	}

	return output[:outLen], nil
}

// Extract takes input keying material and salt, and returns a pseudorandom key
func Extract(salt, secret []byte) []byte {
	if salt == nil {
		salt = make([]byte, types.WC_SHA256_DIGEST_SIZE)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	return extractor.Sum(nil)
}

// Expand takes a pseudorandom key and info string and generates output keying material
func Expand(prk []byte, info []byte, length int) ([]byte, error) {
	if length > 255*types.WC_SHA256_DIGEST_SIZE {
		return nil, errors.New("requested output too long")
	}

	output := make([]byte, 0, length)
	counter := byte(1)
	prev := []byte{}

	for len(output) < length {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		output = append(output, prev...)
		counter++
	}

	return output[:length], nil
}
