package ecc

import (
	"errors"
	"fmt"
)

// #cgo CFLAGS: -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
/*
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

// Function declarations
extern int wc_ecc_init(ecc_key* key);
extern int wc_ecc_free(ecc_key* key);
extern int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key);
extern int wc_ecc_export_private_only(ecc_key* key, byte* out, word32* outLen);
extern int wc_ecc_export_x963(ecc_key* key, byte* out, word32* outlen);
extern int wc_ecc_import_private_key_ex(const byte* priv, word32 privSz, const byte* pub, word32 pubSz, ecc_key* key, int curve_id);
extern int wc_ecc_import_x963_ex(const byte* in, word32 inLen, ecc_key* key, int curve_id);
extern int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32* outlen, WC_RNG* rng, ecc_key* key);
extern int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash, word32 hashlen, int* stat, ecc_key* key);
extern int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out, word32* outlen);
extern int wc_InitRng(WC_RNG* rng);
extern int wc_FreeRng(WC_RNG* rng);
extern int wc_ecc_set_curve(ecc_key* key, int keysize, int curve_id);
extern int wc_ecc_check_key(ecc_key* key);
extern int wc_ecc_get_curve_size_from_id(int curve_id);
extern int wc_ecc_make_pub(ecc_key* key, ecc_point* pubOut);
extern int wc_ecc_export_public_raw(ecc_key* key, byte* qx, word32* qxLen, byte* qy, word32* qyLen);
*/
import "C"

const (
	// ECC_SECP256R1 is the NIST P-256 curve
	ECC_SECP256R1 = int(C.ECC_SECP256R1)

	// WC_ECC_P256_PRIVATE_KEY_SIZE is the size of a SECP256R1 private key in bytes
	WC_ECC_P256_PRIVATE_KEY_SIZE = 32

	// WC_ECC_P256_PUBLIC_KEY_SIZE is the size of a SECP256R1 public key in bytes
	WC_ECC_P256_PUBLIC_KEY_SIZE = 65

	// WC_ECC_P256_SIGNATURE_SIZE is the size of a SECP256R1 signature in bytes
	WC_ECC_P256_SIGNATURE_SIZE = 72
)

// Key represents an ECC key
type Key struct {
	key *C.ecc_key
}

// GenerateKey generates a new ECC key pair
func GenerateKey(curve int, rng []byte) ([]byte, []byte, error) {
	if curve != ECC_SECP256R1 {
		return nil, nil, errors.New("unsupported curve")
	}

	key := &Key{key: &C.ecc_key{}}
	if err := C.wc_ecc_init(key.key); err != 0 {
		return nil, nil, fmt.Errorf("initializing key: %v", err)
	}
	curveSize := C.wc_ecc_get_curve_size_from_id(C.int(ECC_SECP256R1))
	if curveSize <= 0 {
		key.Free()
		return nil, nil, fmt.Errorf("getting curve size: %v", curveSize)
	}
	if err := C.wc_ecc_set_curve(key.key, curveSize, C.int(ECC_SECP256R1)); err != 0 {
		key.Free()
		return nil, nil, fmt.Errorf("setting curve: %v", err)
	}
	defer key.Free()

	cRng := C.WC_RNG{}
	if err := C.wc_InitRng(&cRng); err != 0 {
		return nil, nil, fmt.Errorf("initializing RNG: %v", err)
	}
	defer C.wc_FreeRng(&cRng)

	if err := C.wc_ecc_make_key(&cRng, curveSize, key.key); err != 0 {
		return nil, nil, fmt.Errorf("generating key: %v", err)
	}

	priv := make([]byte, WC_ECC_P256_PRIVATE_KEY_SIZE)
	var privLen C.word32 = C.word32(WC_ECC_P256_PRIVATE_KEY_SIZE)
	
	if err := C.wc_ecc_export_private_only(key.key, (*C.byte)(&priv[0]), &privLen); err != 0 {
		return nil, nil, fmt.Errorf("exporting private key: %v", err)
	}

	pub := make([]byte, WC_ECC_P256_PUBLIC_KEY_SIZE)
	var pubLen C.word32 = C.word32(WC_ECC_P256_PUBLIC_KEY_SIZE)
	if err := C.wc_ecc_export_x963(key.key, (*C.byte)(&pub[0]), &pubLen); err != 0 {
		return nil, nil, fmt.Errorf("exporting public key: %v", err)
	}

	return pub[:pubLen], priv[:privLen], nil
}

// Raw returns the raw bytes of the private key
func (k *Key) Raw() []byte {
	if k == nil || k.key == nil {
		return nil
	}

	priv := make([]byte, WC_ECC_P256_PRIVATE_KEY_SIZE)
	var privLen C.word32
	if err := C.wc_ecc_export_private_only(k.key, (*C.byte)(&priv[0]), &privLen); err != 0 {
		return nil
	}
	return priv[:privLen]
}

// Public returns the public key
func (k *Key) Public() *Key {
	if k == nil || k.key == nil {
		return nil
	}

	pub := &Key{key: &C.ecc_key{}}
	if err := C.wc_ecc_init(pub.key); err != 0 {
		return nil
	}

	pubData := make([]byte, WC_ECC_P256_PUBLIC_KEY_SIZE)
	var pubLen C.word32 = C.word32(WC_ECC_P256_PUBLIC_KEY_SIZE)

	if err := C.wc_ecc_export_x963(k.key, (*C.byte)(&pubData[0]), &pubLen); err != 0 {
		pub.Free()
		return nil
	}

	if err := C.wc_ecc_import_x963_ex((*C.byte)(&pubData[0]), pubLen, pub.key, C.int(ECC_SECP256R1)); err != 0 {
		pub.Free()
		return nil
	}

	return pub
}

// Sign signs a message using the private key
func Sign(priv *Key, message []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, errors.New("invalid private key")
	}

	if err := C.wc_ecc_check_key(priv.key); err != 0 {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	rng := C.WC_RNG{}
	if err := C.wc_InitRng(&rng); err != 0 {
		return nil, fmt.Errorf("initializing RNG: %v", err)
	}
	defer C.wc_FreeRng(&rng)

	sig := make([]byte, WC_ECC_P256_SIGNATURE_SIZE)
	var sigLen C.word32 = C.word32(WC_ECC_P256_SIGNATURE_SIZE)

	if err := C.wc_ecc_sign_hash((*C.byte)(&message[0]), C.word32(len(message)), (*C.byte)(&sig[0]), &sigLen, &rng, priv.key); err != 0 {
		return nil, fmt.Errorf("signing message: %v", err)
	}

	return sig[:sigLen], nil
}

// Verify verifies a signature using the public key
func Verify(pub []byte, message []byte, sig []byte) bool {
	key, err := ImportPublic(ECC_SECP256R1, pub)
	if err != nil {
		return false
	}
	defer key.Free()

	var verified C.int
	if err := C.wc_ecc_verify_hash((*C.byte)(&sig[0]), C.word32(len(sig)), (*C.byte)(&message[0]), C.word32(len(message)), &verified, key.key); err != 0 {
		return false
	}

	return verified == 1
}

// ImportPrivate imports a private key
func ImportPrivate(curve int, data []byte) (*Key, error) {
	if curve != ECC_SECP256R1 {
		return nil, errors.New("unsupported curve")
	}
	if len(data) != WC_ECC_P256_PRIVATE_KEY_SIZE {
		return nil, errors.New("invalid private key size")
	}

	key := &Key{key: &C.ecc_key{}}
	if err := C.wc_ecc_init(key.key); err != 0 {
		return nil, fmt.Errorf("initializing key: %v", err)
	}

	curveSize := C.wc_ecc_get_curve_size_from_id(C.int(ECC_SECP256R1))
	if curveSize <= 0 {
		key.Free()
		return nil, fmt.Errorf("getting curve size: %v", curveSize)
	}
	if err := C.wc_ecc_set_curve(key.key, curveSize, C.int(ECC_SECP256R1)); err != 0 {
		key.Free()
		return nil, fmt.Errorf("setting curve: %v", err)
	}

	if err := C.wc_ecc_import_private_key_ex((*C.byte)(&data[0]), C.word32(len(data)), nil, 0, key.key, C.int(ECC_SECP256R1)); err != 0 {
		key.Free()
		return nil, fmt.Errorf("importing private key: %v", err)
	}

	// Generate public key from private key
	if err := C.wc_ecc_make_pub(key.key, nil); err != 0 {
		key.Free()
		return nil, fmt.Errorf("generating public key: %v", err)
	}

	// Verify the key is valid
	if err := C.wc_ecc_check_key(key.key); err != 0 {
		key.Free()
		return nil, fmt.Errorf("invalid key: %v", err)
	}

	return key, nil
}

// ImportPublic imports a public key
func ImportPublic(curve int, data []byte) (*Key, error) {
	if curve != ECC_SECP256R1 {
		return nil, errors.New("unsupported curve")
	}
	if len(data) != WC_ECC_P256_PUBLIC_KEY_SIZE {
		return nil, errors.New("invalid public key size")
	}

	key := &Key{key: &C.ecc_key{}}
	if err := C.wc_ecc_init(key.key); err != 0 {
		return nil, fmt.Errorf("initializing key: %v", err)
	}

	if err := C.wc_ecc_import_x963_ex((*C.byte)(&data[0]), C.word32(len(data)), key.key, C.int(ECC_SECP256R1)); err != 0 {
		key.Free()
		return nil, fmt.Errorf("importing public key: %v", err)
	}

	return key, nil
}

// ExportPublicFromPrivate exports the public key from a private key
func ExportPublicFromPrivate(priv *Key) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, errors.New("invalid private key")
	}

	pub := make([]byte, WC_ECC_P256_PUBLIC_KEY_SIZE)
	var pubLen C.word32 = C.word32(WC_ECC_P256_PUBLIC_KEY_SIZE)

	if err := C.wc_ecc_export_x963(priv.key, (*C.byte)(&pub[0]), &pubLen); err != 0 {
		return nil, fmt.Errorf("exporting public key: %v", err)
	}

	return pub[:pubLen], nil
}

// SharedSecret computes the shared secret between a private key and a public key
func SharedSecret(priv *Key, pub []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, errors.New("invalid private key")
	}

	pubKey, err := ImportPublic(ECC_SECP256R1, pub)
	if err != nil {
		return nil, fmt.Errorf("importing public key: %v", err)
	}
	defer pubKey.Free()

	secret := make([]byte, WC_ECC_P256_PRIVATE_KEY_SIZE)
	var secretLen C.word32

	if err := C.wc_ecc_shared_secret(priv.key, pubKey.key, (*C.byte)(&secret[0]), &secretLen); err != 0 {
		return nil, fmt.Errorf("computing shared secret: %v", err)
	}

	return secret[:secretLen], nil
}

// Free releases the memory associated with the key
func (k *Key) Free() {
	if k != nil && k.key != nil {
		C.wc_ecc_free(k.key)
		k.key = nil
	}
}
