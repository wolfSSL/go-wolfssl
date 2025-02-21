// Package cgo provides CGo bindings for wolfSSL
package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
*/
import "C"
import "unsafe"

// Constants for AES operations
const (
    AES_ENCRYPTION = C.AES_ENCRYPTION
    AES_DECRYPTION = C.AES_DECRYPTION
)

// Aes represents an AES cipher context
type Aes struct {
    aes C.Aes
}

// NewAes creates a new AES cipher
func NewAes() (*Aes, error) {
    aes := &Aes{}
    ret := C.wc_AesInit(&aes.aes, nil, -1)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    return aes, nil
}

// SetKey sets the key for AES encryption/decryption
func (a *Aes) SetKey(key []byte, dir int) error {
    ret := C.wc_AesSetKey(&a.aes, (*C.byte)(unsafe.Pointer(&key[0])), C.word32(len(key)), nil, C.int(dir))
    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}

// SetIV sets the IV for AES encryption/decryption
func (a *Aes) SetIV(iv []byte) error {
    ret := C.wc_AesSetIV(&a.aes, (*C.byte)(unsafe.Pointer(&iv[0])))
    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}

// Free frees the AES cipher
func (a *Aes) Free() {
    C.wc_AesFree(&a.aes)
}

// GCMEncrypt encrypts data using AES-GCM
func (a *Aes) GCMEncrypt(nonce []byte, plaintext []byte, aad []byte, out []byte) error {
    if len(nonce) != 12 {
        return WolfSSLError(-1)
    }
    if len(out) < len(plaintext)+16 {
        return WolfSSLError(-1)
    }

    var aadPtr *C.byte
    var aadLen C.word32
    if len(aad) > 0 {
        aadPtr = (*C.byte)(unsafe.Pointer(&aad[0]))
        aadLen = C.word32(len(aad))
    }

    ret := C.wc_AesGcmEncrypt(&a.aes,
        (*C.byte)(unsafe.Pointer(&out[0])),
        (*C.byte)(unsafe.Pointer(&plaintext[0])), C.word32(len(plaintext)),
        (*C.byte)(unsafe.Pointer(&nonce[0])), C.word32(len(nonce)),
        aadPtr, aadLen,
        (*C.byte)(unsafe.Pointer(&out[len(plaintext)])), C.word32(16))
    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}

// GCMDecrypt decrypts data using AES-GCM
func (a *Aes) GCMDecrypt(nonce []byte, ciphertext []byte, aad []byte, out []byte) error {
    if len(nonce) != 12 {
        return WolfSSLError(-1)
    }
    if len(ciphertext) < 16 {
        return WolfSSLError(-1)
    }
    if len(out) < len(ciphertext)-16 {
        return WolfSSLError(-1)
    }

    var aadPtr *C.byte
    var aadLen C.word32
    if len(aad) > 0 {
        aadPtr = (*C.byte)(unsafe.Pointer(&aad[0]))
        aadLen = C.word32(len(aad))
    }

    ret := C.wc_AesGcmDecrypt(&a.aes,
        (*C.byte)(unsafe.Pointer(&out[0])),
        (*C.byte)(unsafe.Pointer(&ciphertext[0])), C.word32(len(ciphertext)-16),
        (*C.byte)(unsafe.Pointer(&nonce[0])), C.word32(len(nonce)),
        (*C.byte)(unsafe.Pointer(&ciphertext[len(ciphertext)-16])), C.word32(16),
        aadPtr, aadLen)
    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}
