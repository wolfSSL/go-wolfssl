package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/pwdbased.h>
// #ifdef NO_AES
// #define AES_BLOCK_SIZE   1
// #define AES_128_KEY_SIZE 1
// #define AES_192_KEY_SIZE 1
// #define AES_256_KEY_SIZE 1
// #define AES_ENCRYPTION   1
// #define AES_DECRYPTION   1
// typedef struct Aes {} Aes;
// int wc_AesInit(Aes* aes, void* heap, int devid) {
//      return -174;
//  }
// int wc_AesFree(Aes* aes) {
//      return -174;
//  }
// int wc_AesSetKey(Aes* aes, const byte* key, word32 len,
//                 const byte* iv, int dir) {
//      return -174;
// }
// #ifndef HAVE_AES_CBC
// int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//      return -174;
// }
// #endif
// #endif
import "C"
import (
    "unsafe"
)

const AES_BLOCK_SIZE   = int(C.AES_BLOCK_SIZE)
const AES_128_KEY_SIZE = int(C.AES_128_KEY_SIZE)
const AES_192_KEY_SIZE = int(C.AES_192_KEY_SIZE)
const AES_256_KEY_SIZE = int(C.AES_256_KEY_SIZE)
const AES_ENCRYPTION   = int(C.AES_ENCRYPTION)
const AES_DECRYPTION   = int(C.AES_DECRYPTION)

const INVALID_DEVID    = int(C.INVALID_DEVID)

type Aes = C.struct_Aes

func Wc_AesInit(aes *C.struct_Aes, heap []byte , devId int) C.int {
        /* TODO: HANDLE NON NIL HEAP */
    return C.wc_AesInit(aes, unsafe.Pointer(nil), C.int(devId))
}

func Wc_AesFree(aes *C.struct_Aes) {
    C.wc_AesFree(aes)
}

func Wc_AesSetKey(aes *C.struct_Aes, key []byte, length int, iv []byte, dir int) C.int {
    return C.wc_AesSetKey(aes, (*C.uchar)(unsafe.Pointer(&key[0])), C.word32(length),(*C.uchar)(unsafe.Pointer(&iv[0])), C.int(dir))
}

func Wc_AesCbcEncrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) C.int {
    return C.wc_AesCbcEncrypt(aes, (*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&in[0])), C.word32(sz))
}

func Wc_AesCbcDecrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) C.int {
    return C.wc_AesCbcDecrypt(aes, (*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&in[0])), C.word32(sz))
}

/* TODO: Move function below to appropriate .go file */
func Wc_PBKDF2(out []byte, pwd []byte, pLen int, salt []byte, saltLen int, iter int, kLen int, typeH int) C.int {
    return C.wc_PBKDF2((*C.uchar)(unsafe.Pointer(&out[0])), (*C.uchar)(unsafe.Pointer(&pwd[0])), C.int(pLen),
            (*C.uchar)(unsafe.Pointer(&salt[0])), C.int(saltLen), C.int(iter), C.int(kLen), C.int(typeH))
}

