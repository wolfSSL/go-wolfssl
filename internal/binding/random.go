package binding

// #cgo CFLAGS: -I${SRCDIR}/../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
import "C"

// Random functions
func RandomBytes(size int) ([]byte, error) {
    var rng C.WC_RNG
    if err := C.wc_InitRng(&rng); err != 0 {
        return nil, WolfSSLError(err)
    }
    defer C.wc_FreeRng(&rng)

    buf := make([]byte, size)
    if err := C.wc_RNG_GenerateBlock(&rng, (*C.byte)(&buf[0]), C.word32(size)); err != 0 {
        return nil, WolfSSLError(err)
    }

    return buf, nil
}
