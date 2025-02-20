// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/kdf.h>
import "C"
import "unsafe"

// HKDF performs HMAC-based Key Derivation Function
func HKDF(hashType int, inputKey []byte, salt []byte, info []byte, outLen int) ([]byte, error) {
    out := make([]byte, outLen)
    ret := C.wc_HKDF(C.int(hashType),
        (*C.byte)(unsafe.Pointer(&inputKey[0])), C.word32(len(inputKey)),
        (*C.byte)(unsafe.Pointer(&salt[0])), C.word32(len(salt)),
        (*C.byte)(unsafe.Pointer(&info[0])), C.word32(len(info)),
        (*C.byte)(unsafe.Pointer(&out[0])), C.word32(outLen))
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    return out, nil
}
