package ecc

import (
	"fmt"
	wolfSSL "github.com/wolfssl/go-wolfssl"
)

const (
	ECC_SECP256R1 = 7 // Value from wolfSSL for SECP256R1
)

// GenerateKey generates a new SECP256R1 key pair
func GenerateKey(curve int, rng []byte) (pub, priv []byte, err error) {
	var key wolfSSL.Ecc_key
	var wcrng wolfSSL.WC_RNG
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, nil, fmt.Errorf("failed to initialize ECC key")
	}
	defer wolfSSL.Wc_ecc_free(&key)
	
	if ret := wolfSSL.Wc_InitRng(&wcrng); ret != 0 {
		return nil, nil, fmt.Errorf("failed to initialize RNG")
	}
	defer wolfSSL.Wc_FreeRng(&wcrng)

	if ret := wolfSSL.Wc_ecc_make_key(&wcrng, 32, &key); ret != 0 {
		return nil, nil, fmt.Errorf("failed to generate key: %d", ret)
	}
	if ret := wolfSSL.Wc_ecc_make_pub_in_priv(&key); ret != 0 {
		return nil, nil, fmt.Errorf("failed to generate key")
	}

	priv = make([]byte, 32)
	privSz := 32
	if ret := wolfSSL.Wc_ecc_export_private_only(&key, priv, &privSz); ret != 0 {
		return nil, nil, fmt.Errorf("failed to export private key")
	}

	pub = make([]byte, 65)
	pubSz := 65
	if ret := wolfSSL.Wc_ecc_export_x963_ex(&key, pub, &pubSz, 0); ret != 0 {
		return nil, nil, fmt.Errorf("failed to export public key")
	}

	return pub, priv, nil
}

// ImportPrivate imports a private key
func ImportPrivate(curve int, priv []byte) (interface{}, error) {
	var key wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, fmt.Errorf("failed to initialize ECC key")
	}

	if ret := wolfSSL.Wc_ecc_import_private_key_ex(priv, len(priv), nil, 0, &key, ECC_SECP256R1); ret != 0 {
		wolfSSL.Wc_ecc_free(&key)
		return nil, fmt.Errorf("failed to import private key: %d", ret)
	}
	if ret := wolfSSL.Wc_ecc_make_pub_in_priv(&key); ret != 0 {
		wolfSSL.Wc_ecc_free(&key)
		return nil, fmt.Errorf("failed to import private key")
	}

	return &key, nil
}

// ImportPublic imports a public key
func ImportPublic(curve int, pub []byte) (interface{}, error) {
	var key wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, fmt.Errorf("failed to initialize ECC key")
	}

	if ret := wolfSSL.Wc_ecc_import_x963_ex(pub, len(pub), &key, ECC_SECP256R1); ret != 0 {
		wolfSSL.Wc_ecc_free(&key)
		return nil, fmt.Errorf("failed to import public key")
	}

	return &key, nil
}

// ExportPublicFromPrivate exports the public key from a private key
func ExportPublicFromPrivate(key interface{}) ([]byte, error) {
	eccKey, ok := key.(*wolfSSL.Ecc_key)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}

	pub := make([]byte, 65)
	pubSz := 65
	if ret := wolfSSL.Wc_ecc_export_x963_ex(eccKey, pub, &pubSz, 0); ret != 0 {
		return nil, fmt.Errorf("failed to export public key")
	}

	return pub, nil
}

// Sign signs a message using a private key
func Sign(key interface{}, msg []byte) ([]byte, error) {
	eccKey, ok := key.(*wolfSSL.Ecc_key)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}

	var rng wolfSSL.WC_RNG
	if ret := wolfSSL.Wc_InitRng(&rng); ret != 0 {
		return nil, fmt.Errorf("failed to initialize RNG")
	}
	defer wolfSSL.Wc_FreeRng(&rng)

	// First hash the message with SHA256
	hash := make([]byte, 32)
	if ret := wolfSSL.Wc_Sha256Hash(msg, len(msg), hash); ret != 0 {
		return nil, fmt.Errorf("failed to hash message")
	}

	sig := make([]byte, 72) // Allow for DER encoding overhead
	sigSz := 72
	if ret := wolfSSL.Wc_ecc_sign_hash(hash, len(hash), sig, &sigSz, &rng, eccKey); ret != 0 {
		return nil, fmt.Errorf("failed to sign message")
	}
	return sig[:sigSz], nil
}

// Verify verifies a signature using a public key
func Verify(key interface{}, msg, sig []byte) error {
	eccKey, ok := key.(*wolfSSL.Ecc_key)
	if !ok {
		return fmt.Errorf("invalid key type")
	}

	// First hash the message with SHA256
	hash := make([]byte, 32)
	if ret := wolfSSL.Wc_Sha256Hash(msg, len(msg), hash); ret != 0 {
		return fmt.Errorf("failed to hash message")
	}

	var status int
	if ret := wolfSSL.Wc_ecc_verify_hash(sig, len(sig), hash, len(hash), &status, eccKey); ret != 0 || status != 1 {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
