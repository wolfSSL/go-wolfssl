package wolfssl

import (
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// Hash functions
func Wc_InitBlake2s() int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_Blake2sUpdate(data []byte) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_Blake2sFinal(out []byte) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_Blake2s_HMAC(key []byte, data []byte, out []byte) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}
