package random

import (
	"fmt"
	wolfSSL "github.com/wolfssl/go-wolfssl"
)

type Reader struct {
	rng wolfSSL.WC_RNG
}

func NewReader() (*Reader, error) {
	var r Reader
	if ret := wolfSSL.Wc_InitRng(&r.rng); ret != 0 {
		return nil, fmt.Errorf("failed to initialize RNG")
	}
	return &r, nil
}

func (r *Reader) Read(p []byte) (n int, err error) {
	if ret := wolfSSL.Wc_RNG_GenerateBlock(&r.rng, p, len(p)); ret != 0 {
		return 0, fmt.Errorf("failed to generate random bytes")
	}
	return len(p), nil
}

func (r *Reader) Close() error {
	if ret := wolfSSL.Wc_FreeRng(&r.rng); ret != 0 {
		return fmt.Errorf("failed to free RNG: %d", ret)
	}
	return nil
}
