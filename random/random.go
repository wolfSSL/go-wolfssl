package random

import (
	"fmt"
	"io"
)

// #cgo CFLAGS: -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
/*
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
*/
import "C"

// Reader implements io.Reader for FIPS-compliant random number generation
type Reader struct {
	rng C.WC_RNG
}

// NewReader creates a new FIPS-compliant random number generator
func NewReader() (*Reader, error) {
	r := &Reader{}
	if ret := C.wc_InitRng(&r.rng); ret != 0 {
		return nil, fmt.Errorf("failed to initialize RNG: %d", ret)
	}
	return r, nil
}

// Read implements io.Reader interface
func (r *Reader) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if ret := C.wc_RNG_GenerateBlock(&r.rng, (*C.byte)(&b[0]), C.word32(len(b))); ret != 0 {
		return 0, fmt.Errorf("failed to generate random bytes: %d", ret)
	}
	return len(b), nil
}

// Close releases the resources associated with the RNG
func (r *Reader) Close() error {
	if ret := C.wc_FreeRng(&r.rng); ret != 0 {
		return fmt.Errorf("failed to free RNG: %d", ret)
	}
	return nil
}

// Reader is a FIPS-compliant replacement for crypto/rand.Reader
var DefaultReader io.Reader = func() io.Reader {
	r, err := NewReader()
	if err != nil {
		panic(fmt.Sprintf("failed to create default RNG: %v", err))
	}
	return r
}()
