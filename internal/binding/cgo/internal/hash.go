package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/hash.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
import "C"
import "unsafe"

const (
    WC_MD5_DIGEST_SIZE = int(C.WC_MD5_DIGEST_SIZE)
    WC_SHA_DIGEST_SIZE = int(C.WC_SHA_DIGEST_SIZE)
    WC_SHA256_DIGEST_SIZE = int(C.WC_SHA256_DIGEST_SIZE)
    WC_SHA384_DIGEST_SIZE = int(C.WC_SHA384_DIGEST_SIZE)
    WC_SHA512_DIGEST_SIZE = int(C.WC_SHA512_DIGEST_SIZE)
    WC_SHA256 = int(C.WC_SHA256)
)

func Wc_Sha256Hash(input []byte, inputSz int, output []byte) int {
    return int(C.wc_Sha256Hash((*C.uchar)(unsafe.Pointer(&input[0])),
               C.word32(inputSz), (*C.uchar)(unsafe.Pointer(&output[0]))))
}
