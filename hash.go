package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
// #ifdef NO_MD5
// #define WC_MD5_DIGEST_SIZE 1
// int wc_Md5Hash(const unsigned char* data, unsigned int len, unsigned char* hash) {
//      return -174;
//  }
// #endif
//
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/hash.h>
import "C"
import (
    "unsafe"
)

const WC_MD5_DIGEST_SIZE = int(C.WC_MD5_DIGEST_SIZE)
const WC_SHA_DIGEST_SIZE = int(C.WC_SHA_DIGEST_SIZE)
const WC_SHA256_DIGEST_SIZE = int(C.WC_SHA256_DIGEST_SIZE)
const WC_SHA384_DIGEST_SIZE = int(C.WC_SHA384_DIGEST_SIZE)
const WC_SHA512_DIGEST_SIZE = int(C.WC_SHA512_DIGEST_SIZE)

const WC_SHA256 = int(C.WC_SHA256)

func Wc_Md5Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Md5Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_ShaHash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_ShaHash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha256Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Sha256Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha384Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Sha384Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}

func Wc_Sha512Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Sha512Hash((*C.uchar)(unsafe.Pointer(&input[0])), C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}
