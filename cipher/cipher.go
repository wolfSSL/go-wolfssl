package cipher

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
)

// Block represents an implementation of block cipher
// using a given key.
type Block interface {
    // BlockSize returns the cipher's block size.
    BlockSize() int

    // Encrypt encrypts the first block in src into dst.
    // Dst and src must overlap entirely or not at all.
    Encrypt(dst, src []byte)

    // Decrypt decrypts the first block in src into dst.
    // Dst and src must overlap entirely or not at all.
    Decrypt(dst, src []byte)
}

// AEAD is a cipher mode providing authenticated encryption with associated data.
type AEAD interface {
    // NonceSize returns the size of the nonce that must be passed to Seal
    // and Open.
    NonceSize() int

    // Overhead returns the maximum difference between the lengths of a
    // plaintext and its ciphertext.
    Overhead() int

    // Seal encrypts and authenticates plaintext, authenticates the
    // additional data and appends the result to dst, returning the updated
    // slice. The nonce must be NonceSize() bytes long and unique for all
    // time, for a given key.
    Seal(dst, nonce, plaintext, additionalData []byte) []byte

    // Open decrypts and authenticates ciphertext, authenticates the
    // additional data and, if successful, appends the resulting plaintext
    // to dst, returning the updated slice. The nonce must be NonceSize()
    // bytes long and both it and the additional data must match the
    // value passed to Seal.
    Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
