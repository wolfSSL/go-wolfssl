package aes

import (
    "github.com/wolfssl/go-wolfssl/cipher"
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
)

type gcm struct {
    key []byte
}

// NewGCM returns the given 128-bit, 192-bit, or 256-bit AES cipher wrapped in Galois Counter Mode.
func NewGCM(c cipher.Block) (cipher.AEAD, error) {
    if c == nil {
        return nil, errors.New("cipher.Block required")
    }

    g := &gcm{
        key: make([]byte, c.BlockSize()),
    }
    c.Encrypt(g.key, g.key)
    return g, nil
}

func (g *gcm) NonceSize() int {
    return cgo.WC_AES_GCM_NONCE_SZ
}

func (g *gcm) Overhead() int {
    return cgo.WC_AES_GCM_AUTH_SZ
}

func (g *gcm) Seal(dst, nonce, plaintext, data []byte) []byte {
    if len(nonce) != g.NonceSize() {
        panic("crypto/cipher: incorrect nonce length given to GCM")
    }

    ret, err := cgo.AesGcmEncrypt(g.key, nonce, data, plaintext)
    if err != nil {
        panic("crypto/cipher: " + err.Error())
    }

    return append(dst, ret...)
}

func (g *gcm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
    if len(nonce) != g.NonceSize() {
        return nil, errors.New("crypto/cipher: incorrect nonce length given to GCM")
    }

    ret, err := cgo.AesGcmDecrypt(g.key, nonce, data, ciphertext)
    if err != nil {
        return nil, errors.New("crypto/cipher: " + err.Error())
    }

    return append(dst, ret...), nil
}
