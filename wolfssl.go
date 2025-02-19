package wolfSSL

// #cgo CFLAGS: -I${SRCDIR}/wolfssl/
// #cgo LDFLAGS: -L${SRCDIR}/lib -lwolfssl
// #include <wolfssl/wolfcrypt/settings.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/sha256.h>
// #include <wolfssl/wolfcrypt/aes.h>
import "C"

// WC_ECC_KEY represents a wolfSSL ECC key
type WC_ECC_KEY C.ecc_key

// WC_RNG represents a wolfSSL random number generator
type WC_RNG C.WC_RNG

// Constants for ECC curves
const (
	ECC_SECP256R1 = C.ECC_SECP256R1
)

// Constants for key sizes
const (
	WC_ECC_P256_PRIVATE_KEY_SIZE = 32
	WC_ECC_P256_PUBLIC_KEY_SIZE  = 65
	WC_ECC_P256_SIGNATURE_SIZE   = 72
)

// Wc_ecc_init initializes an ECC key
func Wc_ecc_init(key *WC_ECC_KEY) int {
	return int(C.wc_ecc_init((*C.ecc_key)(key)))
}

// Wc_ecc_free frees an ECC key
func Wc_ecc_free(key *WC_ECC_KEY) {
	C.wc_ecc_free((*C.ecc_key)(key))
}

// Wc_ecc_make_key generates a new ECC key
func Wc_ecc_make_key(rng *WC_RNG, size int, key *WC_ECC_KEY) int {
	return int(C.wc_ecc_make_key((*C.WC_RNG)(rng), C.int(size), (*C.ecc_key)(key)))
}

// Wc_ecc_export_x963 exports a public key in ANSI X9.63 format
func Wc_ecc_export_x963(key *WC_ECC_KEY, out []byte, outLen *int) int {
	return int(C.wc_ecc_export_x963((*C.ecc_key)(key), (*C.byte)(&out[0]), (*C.word32)(outLen)))
}

// Wc_ecc_import_x963_ex imports a public key in ANSI X9.63 format
func Wc_ecc_import_x963_ex(in []byte, inLen int, key *WC_ECC_KEY, curve int) int {
	return int(C.wc_ecc_import_x963_ex((*C.byte)(&in[0]), C.word32(inLen), (*C.ecc_key)(key), C.int(curve)))
}

// Wc_ecc_export_private_only exports only the private key
func Wc_ecc_export_private_only(key *WC_ECC_KEY, out []byte, outLen *int) int {
	return int(C.wc_ecc_export_private_only((*C.ecc_key)(key), (*C.byte)(&out[0]), (*C.word32)(outLen)))
}

// Wc_ecc_import_private_key_ex imports a private key
func Wc_ecc_import_private_key_ex(priv []byte, privSz int, pub []byte, pubSz int, key *WC_ECC_KEY, curve int) int {
	return int(C.wc_ecc_import_private_key_ex((*C.byte)(&priv[0]), C.word32(privSz), (*C.byte)(&pub[0]), C.word32(pubSz), (*C.ecc_key)(key), C.int(curve)))
}

// Wc_ecc_sign_hash signs a hash with an ECC key
func Wc_ecc_sign_hash(in []byte, inLen int, out []byte, outLen *int, rng *WC_RNG, key *WC_ECC_KEY) int {
	return int(C.wc_ecc_sign_hash((*C.byte)(&in[0]), C.word32(inLen), (*C.byte)(&out[0]), (*C.word32)(outLen), (*C.WC_RNG)(rng), (*C.ecc_key)(key)))
}

// Wc_ecc_verify_hash verifies an ECC signature
func Wc_ecc_verify_hash(sig []byte, sigLen int, hash []byte, hashLen int, status *int, key *WC_ECC_KEY) int {
	return int(C.wc_ecc_verify_hash((*C.byte)(&sig[0]), C.word32(sigLen), (*C.byte)(&hash[0]), C.word32(hashLen), (*C.int)(status), (*C.ecc_key)(key)))
}

// Wc_ecc_shared_secret computes a shared secret
func Wc_ecc_shared_secret(priv *WC_ECC_KEY, pub *WC_ECC_KEY, out []byte, outLen *int) int {
	return int(C.wc_ecc_shared_secret((*C.ecc_key)(priv), (*C.ecc_key)(pub), (*C.byte)(&out[0]), (*C.word32)(outLen)))
}

// Wc_InitRng initializes a random number generator
func Wc_InitRng(rng *WC_RNG) int {
	return int(C.wc_InitRng((*C.WC_RNG)(rng)))
}

// Wc_FreeRng frees a random number generator
func Wc_FreeRng(rng *WC_RNG) int {
	return int(C.wc_FreeRng((*C.WC_RNG)(rng)))
}
