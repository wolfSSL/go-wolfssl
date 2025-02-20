// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/settings.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
// #include <wolfssl/wolfcrypt/types.h>
// #include <wolfssl/wolfcrypt/wc_port.h>
import "C"
import "unsafe"

// AesGcmEncrypt encrypts data using AES-GCM
func AesGcmEncrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
    var aes C.Aes
    ret := C.wc_AesInit(&aes, nil, -1)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_AesFree(&aes)

    ret = C.wc_AesGcmSetKey(&aes, (*C.byte)(unsafe.Pointer(&key[0])), C.word32(len(key)))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    ciphertext := make([]byte, len(plaintext))
    authTag := make([]byte, WC_AES_GCM_AUTH_SZ)

    ret = C.wc_AesGcmEncrypt(&aes,
        (*C.byte)(unsafe.Pointer(&ciphertext[0])),
        (*C.byte)(unsafe.Pointer(&plaintext[0])),
        C.word32(len(plaintext)),
        (*C.byte)(unsafe.Pointer(&nonce[0])),
        C.word32(len(nonce)),
        (*C.byte)(unsafe.Pointer(&authTag[0])),
        C.word32(WC_AES_GCM_AUTH_SZ),
        (*C.byte)(unsafe.Pointer(&aad[0])),
        C.word32(len(aad)))

    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    // Combine ciphertext and auth tag
    result := make([]byte, len(ciphertext)+len(authTag))
    copy(result, ciphertext)
    copy(result[len(ciphertext):], authTag)

    return result, nil
}

// AesGcmDecrypt decrypts data using AES-GCM
func AesGcmDecrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < WC_AES_GCM_AUTH_SZ {
        return nil, WolfSSLError(-1)
    }

    var aes C.Aes
    ret := C.wc_AesInit(&aes, nil, -1)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_AesFree(&aes)

    ret = C.wc_AesGcmSetKey(&aes, (*C.byte)(unsafe.Pointer(&key[0])), C.word32(len(key)))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    // Split ciphertext and auth tag
    actualCiphertext := ciphertext[:len(ciphertext)-WC_AES_GCM_AUTH_SZ]
    authTag := ciphertext[len(ciphertext)-WC_AES_GCM_AUTH_SZ:]

    plaintext := make([]byte, len(actualCiphertext))

    ret = C.wc_AesGcmDecrypt(&aes,
        (*C.byte)(unsafe.Pointer(&plaintext[0])),
        (*C.byte)(unsafe.Pointer(&actualCiphertext[0])),
        C.word32(len(actualCiphertext)),
        (*C.byte)(unsafe.Pointer(&nonce[0])),
        C.word32(len(nonce)),
        (*C.byte)(unsafe.Pointer(&authTag[0])),
        C.word32(WC_AES_GCM_AUTH_SZ),
        (*C.byte)(unsafe.Pointer(&aad[0])),
        C.word32(len(aad)))

    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    return plaintext, nil
}
