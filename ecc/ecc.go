package ecc

import (
	"fmt"
	wolfSSL "github.com/wolfssl/go-wolfssl"
	"github.com/wolfssl/go-wolfssl/internal/binding"
)

// GenerateKey generates a new SECP256R1 key pair
func GenerateKey(curve int, rng []byte) (pub, priv []byte, err error) {
	var key wolfSSL.WC_ECC_KEY
	var wcrng wolfSSL.WC_RNG
	if ret := wolfSSL.Wc_InitRng(&wcrng); ret != 0 {
		return nil, nil, fmt.Errorf("failed to initialize RNG")
	}
	defer wolfSSL.Wc_FreeRng(&wcrng)

	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, nil, fmt.Errorf("failed to initialize ECC key")
	}
	defer wolfSSL.Wc_ecc_free(&key)

	if ret := wolfSSL.Wc_ecc_make_key(&wcrng, 32, &key); ret != 0 {
		return nil, nil, fmt.Errorf("failed to generate key")
	}

	priv = make([]byte, wolfSSL.WC_ECC_P256_PRIVATE_KEY_SIZE)
	privSz := wolfSSL.WC_ECC_P256_PRIVATE_KEY_SIZE
	if ret := wolfSSL.Wc_ecc_export_private_only(&key, priv, &privSz); ret != 0 {
		return nil, nil, fmt.Errorf("failed to export private key")
	}

	pub = make([]byte, wolfSSL.WC_ECC_P256_PUBLIC_KEY_SIZE)
	pubSz := wolfSSL.WC_ECC_P256_PUBLIC_KEY_SIZE
	if ret := wolfSSL.Wc_ecc_export_x963(&key, pub, &pubSz); ret != 0 {
		return nil, nil, fmt.Errorf("failed to export public key")
	}

	return pub[:pubSz], priv[:privSz], nil
}

// ImportPrivate imports a private key
func ImportPrivate(curve int, priv []byte) (*wolfSSL.WC_ECC_KEY, error) {
	var key wolfSSL.WC_ECC_KEY
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, fmt.Errorf("failed to initialize ECC key")
	}

	if ret := wolfSSL.Wc_ecc_import_private_key_ex(priv, len(priv), nil, 0, &key, curve); ret != 0 {
		wolfSSL.Wc_ecc_free(&key)
		return nil, fmt.Errorf("failed to import private key")
	}

	return &key, nil
}

// ImportPublic imports a public key
func ImportPublic(curve int, pub []byte) (*wolfSSL.WC_ECC_KEY, error) {
	var key wolfSSL.WC_ECC_KEY
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, fmt.Errorf("failed to initialize ECC key")
	}

	if ret := wolfSSL.Wc_ecc_import_x963_ex(pub, len(pub), &key, curve); ret != 0 {
		wolfSSL.Wc_ecc_free(&key)
		return nil, fmt.Errorf("failed to import public key")
	}

	return &key, nil
}

// ExportPublicFromPrivate exports the public key from a private key
func ExportPublicFromPrivate(key *wolfSSL.WC_ECC_KEY) ([]byte, error) {
	pub := make([]byte, wolfSSL.WC_ECC_P256_PUBLIC_KEY_SIZE)
	pubSz := wolfSSL.WC_ECC_P256_PUBLIC_KEY_SIZE
	if ret := wolfSSL.Wc_ecc_export_x963(key, pub, &pubSz); ret != 0 {
		return nil, fmt.Errorf("failed to export public key")
	}

	return pub[:pubSz], nil
}

// Sign signs a message using a private key
func Sign(key *wolfSSL.WC_ECC_KEY, msg []byte) ([]byte, error) {
	var rng wolfSSL.WC_RNG
	if ret := wolfSSL.Wc_InitRng(&rng); ret != 0 {
		return nil, fmt.Errorf("failed to initialize RNG")
	}
	defer wolfSSL.Wc_FreeRng(&rng)

	sig := make([]byte, wolfSSL.WC_ECC_P256_SIGNATURE_SIZE)
	sigSz := wolfSSL.WC_ECC_P256_SIGNATURE_SIZE
	if ret := wolfSSL.Wc_ecc_sign_hash(msg, len(msg), sig, &sigSz, &rng, key); ret != 0 {
		return nil, fmt.Errorf("failed to sign message")
	}

	return sig[:sigSz], nil
}

// Verify verifies a signature using a public key
func Verify(key *wolfSSL.WC_ECC_KEY, msg, sig []byte) error {
	var status int
	if ret := wolfSSL.Wc_ecc_verify_hash(sig, len(sig), msg, len(msg), &status, key); ret != 0 {
		return fmt.Errorf("failed to verify signature")
	}

	if status != 1 {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// SharedSecret computes the shared secret between a private and public key
func SharedSecret(priv, pub *wolfSSL.WC_ECC_KEY) ([]byte, error) {
	secret := make([]byte, wolfSSL.WC_ECC_P256_PRIVATE_KEY_SIZE)
	secretSz := wolfSSL.WC_ECC_P256_PRIVATE_KEY_SIZE

	if ret := wolfSSL.Wc_ecc_shared_secret(priv, pub, secret, &secretSz); ret != 0 {
		return nil, fmt.Errorf("failed to compute shared secret")
	}

	return secret[:secretSz], nil
}
