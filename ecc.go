package wolfSSL

import (
	"github.com/wolfssl/go-wolfssl/internal/types"
)

// ECC functions
func Wc_ecc_init() int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_free() int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_make_key(rng *types.WC_RNG, size int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_make_pub_in_priv() int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_set_rng(rng *types.WC_RNG) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_export_private_only(out []byte, outLen int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_export_x963_ex(out []byte, outLen int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_import_private_key_ex(priv []byte, privLen int, pub []byte, pubLen int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_import_x963_ex(in []byte, inLen int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_sign_hash(in []byte, inLen int, out []byte, outLen int, rng *types.WC_RNG) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_verify_hash(sig []byte, sigLen int, hash []byte, hashLen int, result *int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}

func Wc_ecc_shared_secret(priv []byte, pub []byte, out []byte, outLen int) int {
	// TODO: Implement using wolfSSL C bindings
	return 0
}
