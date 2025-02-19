package random

import (
	"fmt"
	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// Reader implements io.Reader for wolfSSL's RNG
type Reader struct {
	rng wolfSSL.WC_RNG
}

// NewReader creates a new Reader
func NewReader() (*Reader, error) {
	var r Reader
	if ret := wolfSSL.Wc_InitRng(&r.rng); ret != 0 {
		return nil, fmt.Errorf("failed to initialize RNG")
	}
	return &r, nil
}

// Read implements io.Reader
func (r *Reader) Read(p []byte) (n int, err error) {
	if ret := wolfSSL.Wc_RNG_GenerateBlock(&r.rng, p, len(p)); ret != 0 {
		return 0, fmt.Errorf("failed to generate random bytes")
	}
	return len(p), nil
}

// Close frees the RNG resources
func (r *Reader) Close() error {
	if ret := wolfSSL.Wc_FreeRng(&r.rng); ret != 0 {
		return fmt.Errorf("failed to free RNG")
	}
	return nil
}
