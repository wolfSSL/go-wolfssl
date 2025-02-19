package wolfSSL

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lwolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
*/
import "C"
import "unsafe"

// WC_ECC_KEY represents a wolfSSL ECC key
type WC_ECC_KEY C.struct_ecc_key

// WC_RNG represents a wolfSSL random number generator
type WC_RNG C.struct_WC_RNG

// WC_SHA256 represents a wolfSSL SHA256 context
type WC_SHA256 C.struct_wc_Sha256

// Constants for key sizes
const (
	WC_ECC_P256_PRIVATE_KEY_SIZE = 32
	WC_ECC_P256_PUBLIC_KEY_SIZE  = 65
	WC_ECC_P256_SIGNATURE_SIZE   = 72
)
