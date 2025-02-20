// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include -DHAVE_AES_GCM
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/settings.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
// #include <wolfssl/wolfcrypt/types.h>
// #include <wolfssl/wolfcrypt/wc_port.h>
import "C"
import "unsafe"

const (
    WC_AES_GCM_AUTH_SZ = 16
)

// AesGcmSetKey sets up AES GCM key
func AesGcmSetKey(aes *C.Aes, key []byte, len C.word32) error {
    ret := C.wc_AesGcmSetKey(aes, (*C.byte)(unsafe.Pointer(&key[0])), len)
    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}

// AesGcmEncrypt encrypts data using AES-GCM
func AesGcmEncrypt(aes *C.Aes, out, in []byte, sz C.word32,
    iv []byte, ivSz C.word32,
    authTag []byte, authTagSz C.word32,
    authIn []byte, authInSz C.word32) error {

    ret := C.wc_AesGcmEncrypt(aes,
        (*C.byte)(unsafe.Pointer(&out[0])),
        (*C.byte)(unsafe.Pointer(&in[0])),
        sz,
        (*C.byte)(unsafe.Pointer(&iv[0])),
        ivSz,
        (*C.byte)(unsafe.Pointer(&authTag[0])),
        authTagSz,
        (*C.byte)(unsafe.Pointer(&authIn[0])),
        authInSz)

    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}

// AesGcmDecrypt decrypts data using AES-GCM
func AesGcmDecrypt(aes *C.Aes, out, in []byte, sz C.word32,
    iv []byte, ivSz C.word32,
    authTag []byte, authTagSz C.word32,
    authIn []byte, authInSz C.word32) error {

    ret := C.wc_AesGcmDecrypt(aes,
        (*C.byte)(unsafe.Pointer(&out[0])),
        (*C.byte)(unsafe.Pointer(&in[0])),
        sz,
        (*C.byte)(unsafe.Pointer(&iv[0])),
        ivSz,
        (*C.byte)(unsafe.Pointer(&authTag[0])),
        authTagSz,
        (*C.byte)(unsafe.Pointer(&authIn[0])),
        authInSz)

    if ret != 0 {
        return WolfSSLError(ret)
    }
    return nil
}
