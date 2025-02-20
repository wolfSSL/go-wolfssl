// Package internal provides low-level bindings to wolfSSL C functions
package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/random.h>
import "C"
import "unsafe"

// RandomRead fills the given byte slice with random data
func RandomRead(b []byte) (int, error) {
    var rng C.WC_RNG
    ret := C.wc_InitRng(&rng)
    if ret != 0 {
        return 0, WolfSSLError(ret)
    }
    defer C.wc_FreeRng(&rng)

    ret = C.wc_RNG_GenerateBlock(&rng, (*C.byte)(unsafe.Pointer(&b[0])), C.word32(len(b)))
    if ret != 0 {
        return 0, WolfSSLError(ret)
    }

    return len(b), nil
}

// Int returns a uniform random value in [0, max)
func Int(max int) (int, error) {
    var rng C.WC_RNG
    ret := C.wc_InitRng(&rng)
    if ret != 0 {
        return 0, WolfSSLError(ret)
    }
    defer C.wc_FreeRng(&rng)

    var n C.word32
    ret = C.wc_RNG_GenerateBlock(&rng, (*C.byte)(unsafe.Pointer(&n)), C.word32(4))
    if ret != 0 {
        return 0, WolfSSLError(ret)
    }

    return int(n) % max, nil
}
