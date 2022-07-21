package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/random.h>
// #ifndef HAVE_ECC
// #define ECC_MAX_SIG_SIZE 1
// typedef struct ecc_key {} ecc_key;
// int wc_ecc_init(ecc_key *key) {
//      return -174;
//  }
// int wc_ecc_free(ecc_key *key) {
//      return -174;
//  }
// int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key) {
//      return -174;
//  }
// int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
//                      WC_RNG* rng, ecc_key* key) {
//      return -174;
//  }
// int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
//                        word32 hashlen, int* res, ecc_key* key) {
//      return -174;
//  }
// #endif
import "C"
import (
    "unsafe"
)

const ECC_MAX_SIG_SIZE = int(C.ECC_MAX_SIG_SIZE)

type Ecc_key = C.struct_ecc_key

func Wc_ecc_init(key *C.struct_ecc_key) C.int {
    return C.wc_ecc_init(key)
}

func Wc_ecc_free(key *C.struct_ecc_key) C.int {
    return C.wc_ecc_free(key)
}

func Wc_ecc_make_key(rng *C.struct_WC_RNG, keySize int, key *C.struct_ecc_key) C.int {
    return C.wc_ecc_make_key(rng, C.int(keySize), key)
}

func Wc_ecc_sign_hash(in []byte, inLen int, out []byte, outLen *int, rng *C.struct_WC_RNG, key *C.struct_ecc_key) C.int {
    return C.wc_ecc_sign_hash((*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),(*C.uchar)(unsafe.Pointer(&out[0])),
                (*C.word32)(unsafe.Pointer(outLen)), rng, key)
}

func Wc_ecc_verify_hash(sig []byte, sigLen int, hash []byte, hashLen int, res *int, key *C.struct_ecc_key) C.int {
    return C.wc_ecc_verify_hash((*C.uchar)(unsafe.Pointer(&sig[0])), C.word32(sigLen),(*C.uchar)(unsafe.Pointer(&hash[0])),
                C.word32(sigLen), (*C.int)(unsafe.Pointer(res)), key)
}
