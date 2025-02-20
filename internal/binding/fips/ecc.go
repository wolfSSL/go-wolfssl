// Package fips provides FIPS-compliant cryptographic functions
package fips

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo/internal"
)

// GenerateKey generates a new ECC key pair
func GenerateKey() (*internal.Ecc_key, error) {
    return internal.GenerateECCKey()
}

// Sign signs a message using an ECC private key
func Sign(key *internal.Ecc_key, msg []byte) ([]byte, error) {
    return internal.SignECC(key, msg)
}

// Verify verifies an ECC signature
func Verify(key *internal.Ecc_key, msg []byte, sig []byte) (bool, error) {
    return internal.VerifyECC(key, msg, sig)
}

// ImportPrivate imports a private key
func ImportPrivate(priv []byte) (*internal.Ecc_key, error) {
    return internal.ImportPrivate(priv)
}

// ImportPublic imports a public key
func ImportPublic(pub []byte) (*internal.Ecc_key, error) {
    return internal.ImportPublic(pub)
}

// ExportPublic exports a public key
func ExportPublic(key *internal.Ecc_key) ([]byte, error) {
    return internal.ExportPublic(key)
}

// SharedSecret computes a shared secret between two ECC keys
func SharedSecret(privKey, pubKey *internal.Ecc_key) ([]byte, error) {
    return internal.SharedSecret(privKey, pubKey)
}
