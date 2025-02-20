package types

// #cgo CFLAGS: -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
/*
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
*/
import "C"

// Sha256 represents a SHA256 hash context
type Sha256 C.wc_Sha256

// Wc_Sha256_Init initializes a SHA256 hash context
func Wc_Sha256_Init(sha *Sha256) int {
	return int(C.wc_InitSha256((*C.wc_Sha256)(sha)))
}

// Wc_Sha256_Update updates the SHA256 hash with data
func Wc_Sha256_Update(sha *Sha256, data []byte) int {
	return int(C.wc_Sha256Update((*C.wc_Sha256)(sha), (*C.byte)(&data[0]), C.word32(len(data))))
}

// Wc_Sha256_Final finalizes the SHA256 hash
func Wc_Sha256_Final(sha *Sha256, hash []byte) int {
	return int(C.wc_Sha256Final((*C.wc_Sha256)(sha), (*C.byte)(&hash[0])))
}
