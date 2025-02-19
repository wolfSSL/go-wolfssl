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

// Constants for ECC curves
const (
	ECC_SECP256R1 = 7 // Value from wolfSSL for SECP256R1
)

// Constants for key sizes
const (
	WC_ECC_P256_PRIVATE_KEY_SIZE = 32
	WC_ECC_P256_PUBLIC_KEY_SIZE  = 65
	WC_ECC_P256_SIGNATURE_SIZE   = 72
)

// Core ECC functions
func Wc_ecc_init(key *WC_ECC_KEY) int {
	return int(C.wc_ecc_init((*C.ecc_key)(key)))
}

func Wc_ecc_free(key *WC_ECC_KEY) {
	C.wc_ecc_free((*C.ecc_key)(key))
}

func Wc_ecc_make_key(rng *WC_RNG, size int, key *WC_ECC_KEY) int {
	return int(C.wc_ecc_make_key((*C.WC_RNG)(rng), C.int(size), (*C.ecc_key)(key)))
}

func Wc_ecc_export_x963(key *WC_ECC_KEY, out []byte, outLen *int) int {
	return int(C.wc_ecc_export_x963((*C.ecc_key)(key), (*C.byte)(&out[0]), (*C.word32)(unsafe.Pointer(outLen))))
}

func Wc_ecc_import_x963_ex(in []byte, inLen int, key *WC_ECC_KEY, curve int) int {
	return int(C.wc_ecc_import_x963_ex((*C.byte)(&in[0]), C.word32(inLen), (*C.ecc_key)(key), C.int(curve)))
}

func Wc_ecc_export_private_only(key *WC_ECC_KEY, out []byte, outLen *int) int {
	return int(C.wc_ecc_export_private_only((*C.ecc_key)(key), (*C.byte)(&out[0]), (*C.word32)(unsafe.Pointer(outLen))))
}

func Wc_ecc_import_private_key_ex(priv []byte, privSz int, pub []byte, pubSz int, key *WC_ECC_KEY, curve int) int {
	return int(C.wc_ecc_import_private_key_ex((*C.byte)(&priv[0]), C.word32(privSz), (*C.byte)(&pub[0]), C.word32(pubSz), (*C.ecc_key)(key), C.int(curve)))
}

func Wc_ecc_sign_hash(in []byte, inLen int, out []byte, outLen *int, rng *WC_RNG, key *WC_ECC_KEY) int {
	return int(C.wc_ecc_sign_hash((*C.byte)(&in[0]), C.word32(inLen), (*C.byte)(&out[0]), (*C.word32)(unsafe.Pointer(outLen)), (*C.WC_RNG)(rng), (*C.ecc_key)(key)))
}

func Wc_ecc_verify_hash(sig []byte, sigLen int, hash []byte, hashLen int, status *int, key *WC_ECC_KEY) int {
	return int(C.wc_ecc_verify_hash((*C.byte)(&sig[0]), C.word32(sigLen), (*C.byte)(&hash[0]), C.word32(hashLen), (*C.int)(status), (*C.ecc_key)(key)))
}

func Wc_ecc_shared_secret(priv *WC_ECC_KEY, pub *WC_ECC_KEY, out []byte, outLen *int) int {
	return int(C.wc_ecc_shared_secret((*C.ecc_key)(priv), (*C.ecc_key)(pub), (*C.byte)(&out[0]), (*C.word32)(unsafe.Pointer(outLen))))
}

// Core RNG functions
func Wc_InitRng(rng *WC_RNG) int {
	return int(C.wc_InitRng((*C.WC_RNG)(rng)))
}

func Wc_FreeRng(rng *WC_RNG) int {
	return int(C.wc_FreeRng((*C.WC_RNG)(rng)))
}

func Wc_RNG_GenerateBlock(rng *WC_RNG, out []byte, sz int) int {
	return int(C.wc_RNG_GenerateBlock((*C.WC_RNG)(rng), (*C.byte)(&out[0]), C.word32(sz)))
}

// Core SHA256 functions
func Wc_Sha256_Init(sha *WC_SHA256) int {
	return int(C.wc_InitSha256((*C.wc_Sha256)(sha)))
}

func Wc_Sha256_Update(sha *WC_SHA256, data []byte, sz int) int {
	return int(C.wc_Sha256Update((*C.wc_Sha256)(sha), (*C.byte)(&data[0]), C.word32(sz)))
}

func Wc_Sha256_Final(sha *WC_SHA256, hash []byte) int {
	return int(C.wc_Sha256Final((*C.wc_Sha256)(sha), (*C.byte)(&hash[0])))
}

func Wc_Sha256Hash(data []byte, sz int, hash []byte) int {
	return int(C.wc_Sha256Hash((*C.byte)(&data[0]), C.word32(sz), (*C.byte)(&hash[0])))
}
