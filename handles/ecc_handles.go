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
	"sort"
	"sync"
	"sync/atomic"
	"unsafe"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// TODO: Remove "encoding/pem" and replace with wolfSSL ASN parsing

// zeroBytes wipes temporary buffers holding secrets. Best effort only: the
// Go runtime may already have copied the bytes elsewhere.
var zeroBytes = func(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

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
// The helpers in this package lock the key for the duration of each
// wolfCrypt call, so an EccKey may be shared between goroutines and Free
// waits for in-flight operations. Code that uses Raw, Rng, CKeyPtr or
// CRngPtr directly must hold Lock (or LockEccKeys) across that use.
type EccKey struct {
	mu     sync.Mutex
	raw    wolfSSL.Ecc_key
	rng    wolfSSL.WC_RNG
	init   bool  // wc_ecc_init has run
	hasRng int32 // atomic; wc_InitRng has run (private-key handles only)
	live   int32 // atomic; additionally, key material is populated
	alg    int32 // atomic; the Algorithm while live
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
	atomic.StoreInt32(&k.hasRng, 1)
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
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.init {
		return
	}
	alg, _ := eccKeyAlgorithm(&k.raw)
	atomic.StoreInt32(&k.alg, int32(alg))
	atomic.StoreInt32(&k.live, 1)
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
// The result is stable only while Lock is held.
func (k *EccKey) IsLive() bool {
	return k != nil && atomic.LoadInt32(&k.live) == 1
}

// testHookAcquired, when set by tests, runs while an operation holds a key
// lock.
var testHookAcquired func()

// acquire locks a live key and returns its unlock function, or returns nil
// (with the key unlocked) if k is nil or not live.
func (k *EccKey) acquire() func() {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	if atomic.LoadInt32(&k.live) == 0 {
		k.mu.Unlock()
		return nil
	}
	if testHookAcquired != nil {
		testHookAcquired()
	}
	return k.mu.Unlock
}

// Lock serializes direct use of Raw, Rng, CKeyPtr and CRngPtr with the
// helpers in this package and with Free. While holding it, do not call
// MarkLive, Free or the package-level helpers on k; they lock k.
func (k *EccKey) Lock() { k.mu.Lock() }

// Unlock releases the lock taken by Lock.
func (k *EccKey) Unlock() { k.mu.Unlock() }

// LockEccKeys locks each distinct non-nil key in a fixed (address) order,
// so callers locking overlapping sets cannot deadlock, and returns a
// function that unlocks them.
func LockEccKeys(keys ...*EccKey) (unlock func()) {
	var locked []*EccKey
	for _, k := range keys {
		dup := k == nil
		for _, l := range locked {
			if l == k {
				dup = true
			}
		}
		if !dup {
			locked = append(locked, k)
		}
	}
	sort.Slice(locked, func(i, j int) bool {
		return uintptr(unsafe.Pointer(locked[i])) < uintptr(unsafe.Pointer(locked[j]))
	})
	for _, k := range locked {
		k.mu.Lock()
	}
	return func() {
		for i := len(locked) - 1; i >= 0; i-- {
			locked[i].mu.Unlock()
		}
	}
}

// Free releases the wolfCrypt key and RNG resources. Safe to call multiple
// times and safe to call on a partially-constructed key (NewEmptyEccKey
// or NewEmptyEccPubKey without MarkLive); subsequent calls are no-ops.
func (k *EccKey) Free() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.init {
		return
	}
	if atomic.LoadInt32(&k.hasRng) == 1 {
		wolfSSL.Wc_FreeRng(&k.rng)
		atomic.StoreInt32(&k.hasRng, 0)
	}
	atomic.StoreInt32(&k.live, 0)
	atomic.StoreInt32(&k.alg, int32(AlgUnknown))
	wolfSSL.Wc_ecc_free(&k.raw)
	k.init = false
	// SetFinalizer to nil to avoid double-free
	runtime.SetFinalizer(k, nil)
}

// Raw returns the underlying wolfCrypt ecc_key for direct use with low-level
// Wc_* APIs (signing, verifying, cert builder, etc.). The returned pointer
// is invalid after Free; hold Lock while using it.
func (k *EccKey) Raw() *wolfSSL.Ecc_key { return &k.raw }

// Rng returns the wolfCrypt RNG associated with this key. Used by signing
// operations that take an RNG argument. Hold Lock while using it.
func (k *EccKey) Rng() *wolfSSL.WC_RNG { return &k.rng }

// Algorithm returns AlgECDSAP256 for a live P-256 key and AlgUnknown for
// any other curve or for a key that has not been marked live.
func (k *EccKey) Algorithm() Algorithm {
	if !k.IsLive() {
		return AlgUnknown
	}
	return Algorithm(atomic.LoadInt32(&k.alg))
}

// CKeyPtr returns the C ecc_key, or nil if k is not live. The caller must
// hold Lock (or LockEccKeys) while calling it and using the pointer.
func (k *EccKey) CKeyPtr() unsafe.Pointer {
	if !k.IsLive() {
		return nil
	}
	return unsafe.Pointer(&k.raw)
}

// CRngPtr returns the key's C WC_RNG, or nil if it has none. The caller
// must hold Lock (or LockEccKeys) while calling it and using the pointer.
func (k *EccKey) CRngPtr() unsafe.Pointer {
	if k == nil || atomic.LoadInt32(&k.hasRng) == 0 {
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
	unlock := k.acquire()
	if unlock == nil {
		return nil, errors.New("handles: EccKey is not live")
	}
	defer unlock()
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
	unlock := k.acquire()
	if unlock == nil {
		return nil, errors.New("handles: EccKey is not live")
	}
	defer unlock()
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
	buf := make([]byte, len(p))
	defer zeroBytes(buf)
	n := wolfSSL.Wc_KeyPemToDer(p, buf, "")
	if n < 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_KeyPemToDer: %d", n)
	}
	der := buf[:n]
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
	unlock := k.acquire()
	if unlock == nil {
		return nil, nil, errors.New("handles: EccKey is not live")
	}
	defer unlock()
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
// Concurrent calls on the same EccKey are serialized by the key's lock.
func SignDigest(k *EccKey, digest []byte) ([]byte, error) {
	unlock := k.acquire()
	if unlock == nil {
		return nil, errors.New("handles: EccKey is not live")
	}
	defer unlock()
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
