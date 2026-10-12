/* ecc_handles.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package handles

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// TODO: Remove "encoding/pem" and replace with wolfSSL ASN parsing

// Algorithm names a wolfCrypt key class.
type Algorithm int

const (
	AlgUnknown Algorithm = iota
	AlgECDSAP256
)

// -----------------------------------------------------------------------------
// EccKey: lifecycle handle for a wolfCrypt ECC key plus its dedicated RNG.
// -----------------------------------------------------------------------------

// EccKey is a wolfCrypt ECC private+public key pair plus an optional
// dedicated RNG. The zero value is not usable; obtain one via
// GenerateP256Key, NewEmptyEccKey, or NewEmptyEccPubKey. Callers must
// Free the key when done; freeing twice is safe.
//
// EccKey is NOT currently thread-safe for use across operations that
// consume the embedded RNG (SignDigest, GenerateP256Key, and any wolfx509 cert
// builder call that takes this key as the signer). Either serialize
// callers or hand each goroutine its own EccKey. Read-only ops
// (Verify, public-key export) are safe to call concurrently.
type EccKey struct {
	raw    wolfSSL.Ecc_key
	rng    wolfSSL.WC_RNG
	init   bool // wc_ecc_init has run
	hasRng bool // wc_InitRng has run (private-key handles only)
	live   bool // additionally, key material is populated
	alg    Algorithm
}

// GenerateP256Key returns a fresh P-256 (secp256r1) ECC key pair generated
// via wolfCrypt's RNG. The returned key holds an embedded RNG suitable for
// signing operations.
func GenerateP256Key() (*EccKey, error) {
	k, err := NewEmptyEccKey()
	if err != nil {
		return nil, err
	}
	if ret := wolfSSL.Wc_ecc_make_key(&k.rng, 32, &k.raw); ret != 0 {
		k.Free()
		return nil, fmt.Errorf("wolfCrypt: wc_ecc_make_key: %d", ret)
	}
	k.MarkLive()
	if k.Algorithm() != AlgECDSAP256 {
		k.Free()
		return nil, errors.New("handles: generated key is not P-256")
	}
	return k, nil
}

// NewEmptyEccKey returns an EccKey with wc_ecc_init + wc_InitRng called but
// no key material populated. Higher-level parse helpers call this, then
// fill in the key bytes via wc_EccPrivateKeyDecode / wc_ecc_import_x963_ex
// / etc., and finally call MarkLive once the key is usable. Free releases
// both the ecc_key and the RNG regardless of whether MarkLive was called,
// so it is safe to defer immediately after construction.
func NewEmptyEccKey() (*EccKey, error) {
	k := &EccKey{}
	if ret := wolfSSL.Wc_ecc_init(&k.raw); ret != 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_ecc_init: %d", ret)
	}
	if ret := wolfSSL.Wc_InitRng(&k.rng); ret != 0 {
		wolfSSL.Wc_ecc_free(&k.raw)
		return nil, fmt.Errorf("wolfCrypt: wc_InitRng: %d", ret)
	}
	k.init = true
	k.hasRng = true
	runtime.SetFinalizer(k, (*EccKey).Free)
	return k, nil
}

// NewEmptyEccPubKey returns an EccKey initialized for public-key use only;
// no RNG is allocated, so signing operations will fail.
func NewEmptyEccPubKey() (*EccKey, error) {
	k := &EccKey{}
	if ret := wolfSSL.Wc_ecc_init(&k.raw); ret != 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_ecc_init: %d", ret)
	}
	k.init = true
	runtime.SetFinalizer(k, (*EccKey).Free)
	return k, nil
}

// MarkLive flags the key as fully populated. Higher-level parse helpers call
// this once they have successfully filled the underlying ecc_key from a DER
// or PEM blob. After MarkLive the key is usable for signing/verification.
// MarkLive also records the key's curve for Algorithm.
func (k *EccKey) MarkLive() {
	k.alg, _ = eccKeyAlgorithm(&k.raw)
	k.live = true
}

// p256SPKIPrefix is the DER SubjectPublicKeyInfo header for an uncompressed
// prime256v1 (P-256) public key.
var p256SPKIPrefix = []byte{
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
	0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
	0x42, 0x00, 0x04,
}

// eccPrivateOnlyE is wolfCrypt's ECC_PRIVATEONLY_E: the key has no public point.
const eccPrivateOnlyE = -246

// eccKeyAlgorithm returns the curve class of key, or AlgUnknown and the
// negative wolfCrypt error if its public key cannot be exported.
func eccKeyAlgorithm(key *wolfSSL.Ecc_key) (Algorithm, int) {
	spki := make([]byte, 160)
	n := wolfSSL.Wc_EccPublicKeyToDer(key, spki, 1)
	if n == eccPrivateOnlyE {
		if ret := wolfSSL.Wc_ecc_make_pub_in_priv(key); ret != 0 {
			return AlgUnknown, ret
		}
		n = wolfSSL.Wc_EccPublicKeyToDer(key, spki, 1)
	}
	if n < 0 {
		return AlgUnknown, n
	}
	if n == len(p256SPKIPrefix)+64 && bytes.Equal(spki[:len(p256SPKIPrefix)], p256SPKIPrefix) {
		return AlgECDSAP256, 0
	}
	return AlgUnknown, 0
}

// IsLive reports whether the key has been generated or successfully parsed
// (i.e. usable for signing/verification operations) and not yet freed.
func (k *EccKey) IsLive() bool { return k != nil && k.live }

// Free releases the wolfCrypt key and RNG resources. Safe to call multiple
// times and safe to call on a partially-constructed key (NewEmptyEccKey
// or NewEmptyEccPubKey without MarkLive); subsequent calls are no-ops.
func (k *EccKey) Free() {
	if k == nil || !k.init {
		return
	}
	if k.hasRng {
		wolfSSL.Wc_FreeRng(&k.rng)
		k.hasRng = false
	}
	wolfSSL.Wc_ecc_free(&k.raw)
	k.init = false
	k.live = false
	// SetFinalizer to nil to avoid double-free
	runtime.SetFinalizer(k, nil)
}

// Raw returns the underlying wolfCrypt ecc_key for direct use with low-level
// Wc_* APIs (signing, verifying, cert builder, etc.). The returned pointer
// is invalid after Free.
func (k *EccKey) Raw() *wolfSSL.Ecc_key { return &k.raw }

// Rng returns the wolfCrypt RNG associated with this key. Used by signing
// operations that take an RNG argument.
func (k *EccKey) Rng() *wolfSSL.WC_RNG { return &k.rng }

// Algorithm returns AlgECDSAP256 for a live P-256 key and AlgUnknown for
// any other curve or for a key that has not been marked live.
func (k *EccKey) Algorithm() Algorithm    { return k.alg }
func (k *EccKey) CKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k.raw) }

func (k *EccKey) CRngPtr() unsafe.Pointer {
	if k == nil || !k.hasRng {
		return nil
	}
	return unsafe.Pointer(&k.rng)
}

// -----------------------------------------------------------------------------
// EccKey marshal/parse helpers
//
// DER/PEM marshal+parse, raw point export, and digest-signing helpers for
// *EccKey.
// -----------------------------------------------------------------------------

// MarshalSEC1DER returns the SEC1 EC-private-key DER encoding of k —
// the body of an "EC PRIVATE KEY" PEM block.
func MarshalSEC1DER(k *EccKey) ([]byte, error) {
	if !k.IsLive() {
		return nil, errors.New("handles: EccKey is not live")
	}
	// 256 bytes comfortably exceeds the worst-case SEC1+pub size for any
	// wolfCrypt-supported curve.
	buf := make([]byte, 256)
	n := wolfSSL.Wc_EccKeyToDer(k.Raw(), buf)
	if n < 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_EccKeyToDer: %d", n)
	}
	return buf[:n], nil
}

// MarshalPKCS8DER returns the key wrapped in an unencrypted PKCS#8
// PrivateKeyInfo DER blob via wc_EccKeyToPKCS8.
func MarshalPKCS8DER(k *EccKey) ([]byte, error) {
	if !k.IsLive() {
		return nil, errors.New("handles: EccKey is not live")
	}
	out := make([]byte, 384)
	outLen := len(out)
	if ret := wolfSSL.Wc_EccKeyToPKCS8(k.Raw(), out, &outLen); ret < 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_EccKeyToPKCS8: %d", ret)
	}
	return out[:outLen], nil
}

// MarshalSEC1PEM returns the key as a PEM-armored SEC1 EC private key
// (block type "EC PRIVATE KEY").
func MarshalSEC1PEM(k *EccKey) ([]byte, error) {
	der, err := MarshalSEC1DER(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// MarshalPKCS8PEM returns the key as a PEM-armored PKCS#8 PrivateKeyInfo
// (block type "PRIVATE KEY"). Used by the autocert account-key cache.
func MarshalPKCS8PEM(k *EccKey) ([]byte, error) {
	der, err := MarshalPKCS8DER(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// errNotP256 reports a well-formed EC private key on a curve other than P-256.
var errNotP256 = errors.New("handles: EC private key is not P-256")

// ParseECPrivateKeyDER parses a SEC1 EC private key DER blob (the body of
// an "EC PRIVATE KEY" PEM) into a fresh EccKey. Only P-256 keys are
// accepted.
func ParseECPrivateKeyDER(der []byte) (*EccKey, error) {
	if len(der) == 0 {
		return nil, errors.New("handles: empty EC private key DER")
	}
	k, err := NewEmptyEccKey()
	if err != nil {
		return nil, err
	}
	idx := 0
	if ret := wolfSSL.Wc_EccPrivateKeyDecode(der, &idx, k.Raw(), len(der)); ret != 0 {
		k.Free()
		return nil, fmt.Errorf("wolfCrypt: wc_EccPrivateKeyDecode: %d", ret)
	}
	alg, ret := eccKeyAlgorithm(k.Raw())
	if ret < 0 {
		k.Free()
		return nil, fmt.Errorf("wolfCrypt: wc_EccPublicKeyToDer: %d", ret)
	}
	if alg != AlgECDSAP256 {
		k.Free()
		return nil, errNotP256
	}
	k.MarkLive()
	return k, nil
}

// ParsePKCS8ECPrivateKeyDER parses an unencrypted PKCS#8 PrivateKeyInfo
// blob containing an EC private key into a fresh EccKey. The PKCS#8
// header is stripped via wc_GetPkcs8TraditionalOffset and the inner SEC1
// body is decoded via wc_EccPrivateKeyDecode.
func ParsePKCS8ECPrivateKeyDER(der []byte) (*EccKey, error) {
	if len(der) == 0 {
		return nil, errors.New("handles: empty PKCS#8 EC private key DER")
	}
	idx := 0
	if ret := wolfSSL.Wc_GetPkcs8TraditionalOffset(der, &idx); ret < 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_GetPkcs8TraditionalOffset: %d", ret)
	}
	return ParseECPrivateKeyDER(der[idx:])
}

// ParseECPrivateKeyPEM parses a PEM-armored EC private key (either SEC1 or
// PKCS#8 encoded; auto-detected via wc_KeyPemToDer) into a fresh EccKey.
func ParseECPrivateKeyPEM(p []byte) (*EccKey, error) {
	if len(p) == 0 {
		return nil, errors.New("handles: empty EC private key PEM")
	}
	der := make([]byte, len(p))
	n := wolfSSL.Wc_KeyPemToDer(p, der, "")
	if n < 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_KeyPemToDer: %d", n)
	}
	der = der[:n]
	k, err := ParseECPrivateKeyDER(der)
	if err == nil || err == errNotP256 {
		return k, err
	}
	return ParsePKCS8ECPrivateKeyDER(der)
}

// PublicRawXY exports the X and Y coordinates of the public point as raw
// big-endian byte strings (32 bytes each for P-256). Used by JWS/JWK
// encoders (RFC 7518 §6.2.1) and anywhere else a pure numeric point
// representation is needed.
func PublicRawXY(k *EccKey) (x, y []byte, err error) {
	if !k.IsLive() {
		return nil, nil, errors.New("handles: EccKey is not live")
	}
	x = make([]byte, 32)
	y = make([]byte, 32)
	xLen := len(x)
	yLen := len(y)
	if ret := wolfSSL.Wc_ecc_export_public_raw(k.Raw(), x, &xLen, y, &yLen); ret != 0 {
		return nil, nil, fmt.Errorf("wolfCrypt: wc_ecc_export_public_raw: %d", ret)
	}
	return x[:xLen], y[:yLen], nil
}

// SignDigest signs a pre-computed hash digest and returns an ASN.1-DER
// encoded ECDSA signature (SEQUENCE { r INTEGER, s INTEGER }). For P-256,
// the caller must supply a 32-byte digest (SHA-256 output).
//
// Not safe to call concurrently with another SignDigest (or any other
// RNG-consuming operation) on the same EccKey: see the EccKey type doc.
func SignDigest(k *EccKey, digest []byte) ([]byte, error) {
	if !k.IsLive() {
		return nil, errors.New("handles: EccKey is not live")
	}
	if len(digest) == 0 {
		return nil, errors.New("handles: SignDigest: empty digest")
	}
	sig := make([]byte, wolfSSL.ECC_MAX_SIG_SIZE)
	sigLen := len(sig)
	if ret := wolfSSL.Wc_ecc_sign_hash(digest, len(digest), sig, &sigLen, k.Rng(), k.Raw()); ret != 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_ecc_sign_hash: %d", ret)
	}
	return sig[:sigLen], nil
}
