package binding

// #cgo CFLAGS: -I${SRCDIR}/../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/hash.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
// #ifdef NO_MD5
// #define WC_MD5_DIGEST_SIZE 1
// int wc_Md5Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifdef NO_SHA
// #define WC_SHA_DIGEST_SIZE 1
// int wc_ShaHash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifdef NO_SHA256
// int wc_Sha256Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifndef WOLFSSL_SHA384
// #define WC_SHA384_DIGEST_SIZE 1
// int wc_Sha384Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
// #ifndef WOLFSSL_SHA512
// int wc_Sha512Hash(const byte* data, word32 len, byte* hash) {
//      return -174;
//  }
// #endif
import "C"
// No imports needed yet

// Hash functions
func Sha256Hash(data []byte) ([32]byte, error) {
    var hash [32]byte
    if err := C.wc_Sha256Hash((*C.byte)(&data[0]), C.word32(len(data)), (*C.byte)(&hash[0])); err != 0 {
        return [32]byte{}, WolfSSLError(err)
    }
    return hash, nil
}
