package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/random.h>
import "C"
import (
    "unsafe"
)

type WC_RNG = C.struct_WC_RNG

func Wc_InitRng(rng *C.struct_WC_RNG) C.int {
    return C.wc_InitRng(rng)
}

func Wc_FreeRng(rng *C.struct_WC_RNG) C.int {
    return C.wc_FreeRng(rng)
}

func Wc_RNG_GenerateBlock(rng *C.struct_WC_RNG, b []byte, sz int) C.int {
    return C.wc_RNG_GenerateBlock(rng, (*C.uchar)(unsafe.Pointer(&b[0])), C.word32(sz))
}
