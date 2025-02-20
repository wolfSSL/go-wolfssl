package main

import (
    "fmt"
    "log"

    "github.com/wolfssl/go-wolfssl"
)

func main() {
    key := make([]byte, wolfssl.WC_AES_256_KEY_SIZE)
    nonce := make([]byte, wolfssl.WC_AES_GCM_NONCE_SZ)
    aad := []byte("additional data")
    plaintext := []byte("Hello, World!")

    // Generate random key and nonce
    if _, err := wolfssl.RandomRead(key); err != nil {
        log.Fatal(err)
    }
    if _, err := wolfssl.RandomRead(nonce); err != nil {
        log.Fatal(err)
    }

    // Encrypt
    ciphertext, err := wolfssl.AesGcmEncrypt(key, nonce, aad, plaintext)
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt
    decrypted, err := wolfssl.AesGcmDecrypt(key, nonce, aad, ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Original: %s\n", plaintext)
    fmt.Printf("Decrypted: %s\n", decrypted)
}
