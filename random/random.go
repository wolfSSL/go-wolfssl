package random

import (
	"fmt"
	"io"
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// reader implements io.Reader for FIPS-compliant random number generation
type reader struct{}

// Reader is a FIPS-compliant replacement for crypto/rand.Reader
var Reader io.Reader = &reader{}

// Read implements io.Reader interface
func (r *reader) Read(b []byte) (n int, err error) {
	rng := new(types.WC_RNG)
	if ret := types.Wc_InitRng(rng); ret != 0 {
		return 0, fmt.Errorf("failed to initialize RNG: %d", ret)
	}
	defer types.Wc_FreeRng(rng)

	if ret := types.Wc_RNG_GenerateBlock(rng, b, len(b)); ret != 0 {
		return 0, fmt.Errorf("failed to generate random bytes: %d", ret)
	}
	return len(b), nil
}
