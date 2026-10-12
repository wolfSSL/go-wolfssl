/* ecc_handles_test.go
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
	"sync"
	"testing"
	"time"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

func TestEccKeyMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		marshal func(*EccKey) ([]byte, error)
		parse   func([]byte) (*EccKey, error)
	}{
		{"SEC1DER", MarshalSEC1DER, ParseECPrivateKeyDER},
		{"SEC1PEM", MarshalSEC1PEM, ParseECPrivateKeyPEM},
		{"PKCS8DER", MarshalPKCS8DER, ParsePKCS8ECPrivateKeyDER},
		{"PKCS8PEM", MarshalPKCS8PEM, ParseECPrivateKeyPEM},
	}

	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := tc.marshal(k)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			k2, err := tc.parse(enc)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer k2.Free()
			enc2, err := tc.marshal(k2)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if !bytes.Equal(enc, enc2) {
				t.Fatalf("round trip mismatch:\n got %x\nwant %x", enc2, enc)
			}
		})
	}
}

func TestEccPrivateKeyToDer(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	buf := make([]byte, 256)
	n := wolfSSL.Wc_EccPrivateKeyToDer(k.Raw(), buf)
	if n <= 0 {
		t.Fatalf("Wc_EccPrivateKeyToDer: %d", n)
	}
	enc := buf[:n]
	k2, err := ParseECPrivateKeyDER(enc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer k2.Free()

	buf2 := make([]byte, 256)
	n2 := wolfSSL.Wc_EccPrivateKeyToDer(k2.Raw(), buf2)
	if n2 <= 0 {
		t.Fatalf("Re - Wc_EccPrivateKeyToDer: %d", n2)
	}
	if enc2 := buf2[:n2]; !bytes.Equal(enc, enc2) {
		t.Fatalf("round trip mismatch:\n got %x\nwant %x", enc2, enc)
	}
}

// eccTestKeyDER generates an ECC key of keySize bytes and returns its SEC1
// private DER and its SubjectPublicKeyInfo DER. Skips if the curve is not
// compiled in.
func eccTestKeyDER(t *testing.T, keySize int) (priv, pub []byte) {
	t.Helper()
	var rng wolfSSL.WC_RNG
	if ret := wolfSSL.Wc_InitRng(&rng); ret != 0 {
		t.Fatalf("Wc_InitRng: %d", ret)
	}
	defer wolfSSL.Wc_FreeRng(&rng)
	var key wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer wolfSSL.Wc_ecc_free(&key)
	if ret := wolfSSL.Wc_ecc_make_key(&rng, keySize, &key); ret != 0 {
		t.Skipf("Wc_ecc_make_key(%d): %d (curve not available)", keySize, ret)
	}
	priv = make([]byte, 512)
	n := wolfSSL.Wc_EccKeyToDer(&key, priv)
	if n <= 0 {
		t.Fatalf("Wc_EccKeyToDer: %d", n)
	}
	pub = make([]byte, 512)
	m := wolfSSL.Wc_EccPublicKeyToDer(&key, pub, 1)
	if m <= 0 {
		t.Fatalf("Wc_EccPublicKeyToDer: %d", m)
	}
	return priv[:n], pub[:m]
}

func TestEccKeyAlgorithmReportsP256Only(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()
	if alg := k.Algorithm(); alg != AlgECDSAP256 {
		t.Fatalf("generated P-256 key Algorithm() = %d, want %d", alg, AlgECDSAP256)
	}

	der, err := MarshalSEC1DER(k)
	if err != nil {
		t.Fatalf("MarshalSEC1DER: %v", err)
	}
	k2, err := ParseECPrivateKeyDER(der)
	if err != nil {
		t.Fatalf("ParseECPrivateKeyDER(P-256): %v", err)
	}
	defer k2.Free()
	if alg := k2.Algorithm(); alg != AlgECDSAP256 {
		t.Fatalf("parsed P-256 key Algorithm() = %d, want %d", alg, AlgECDSAP256)
	}

	_, pub384 := eccTestKeyDER(t, 48)
	pk, err := NewEmptyEccPubKey()
	if err != nil {
		t.Fatalf("NewEmptyEccPubKey: %v", err)
	}
	defer pk.Free()
	idx := 0
	if ret := wolfSSL.Wc_EccPublicKeyDecode(pub384, &idx, pk.Raw(), len(pub384)); ret != 0 {
		t.Fatalf("Wc_EccPublicKeyDecode(P-384): %d", ret)
	}
	pk.MarkLive()
	if alg := pk.Algorithm(); alg == AlgECDSAP256 {
		t.Fatal("P-384 public key reported as AlgECDSAP256")
	}
}

// eccTestPKCS8DER generates an ECC key of keySize bytes and returns it as
// unencrypted PKCS#8 DER. Skips if the curve is not compiled in.
func eccTestPKCS8DER(t *testing.T, keySize int) []byte {
	t.Helper()
	var rng wolfSSL.WC_RNG
	if ret := wolfSSL.Wc_InitRng(&rng); ret != 0 {
		t.Fatalf("Wc_InitRng: %d", ret)
	}
	defer wolfSSL.Wc_FreeRng(&rng)
	var key wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer wolfSSL.Wc_ecc_free(&key)
	if ret := wolfSSL.Wc_ecc_make_key(&rng, keySize, &key); ret != 0 {
		t.Skipf("Wc_ecc_make_key(%d): %d (curve not available)", keySize, ret)
	}
	der := make([]byte, 512)
	derLen := len(der)
	if ret := wolfSSL.Wc_EccKeyToPKCS8(&key, der, &derLen); ret < 0 {
		t.Fatalf("Wc_EccKeyToPKCS8: %d", ret)
	}
	return der[:derLen]
}

func TestParseECPrivateKeyPEMReportsNonP256(t *testing.T) {
	priv384, _ := eccTestKeyDER(t, 48)
	pkcs8384 := eccTestPKCS8DER(t, 48)
	blocks := []*pem.Block{
		{Type: "EC PRIVATE KEY", Bytes: priv384},
		{Type: "PRIVATE KEY", Bytes: pkcs8384},
	}
	for _, b := range blocks {
		k, err := ParseECPrivateKeyPEM(pem.EncodeToMemory(b))
		if err == nil {
			k.Free()
			t.Fatalf("ParseECPrivateKeyPEM accepted a P-384 %q key", b.Type)
		}
		if err != errNotP256 {
			t.Fatalf("ParseECPrivateKeyPEM(P-384 %q) = %v, want %v", b.Type, err, errNotP256)
		}
	}
}

func TestParseECPrivateKeyDERRejectsNonP256(t *testing.T) {
	priv384, _ := eccTestKeyDER(t, 48)
	k, err := ParseECPrivateKeyDER(priv384)
	if err == nil {
		k.Free()
		t.Fatal("ParseECPrivateKeyDER accepted a P-384 key")
	}
}

func TestParseECPrivateKeyDERAcceptsP256WithoutPublicKey(t *testing.T) {
	var rng wolfSSL.WC_RNG
	if ret := wolfSSL.Wc_InitRng(&rng); ret != 0 {
		t.Fatalf("Wc_InitRng: %d", ret)
	}
	defer wolfSSL.Wc_FreeRng(&rng)
	var key wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer wolfSSL.Wc_ecc_free(&key)
	if ret := wolfSSL.Wc_ecc_make_key(&rng, 32, &key); ret != 0 {
		t.Fatalf("Wc_ecc_make_key: %d", ret)
	}
	der := make([]byte, 256)
	n := wolfSSL.Wc_EccPrivateKeyToDer(&key, der)
	if n <= 0 {
		t.Skipf("Wc_EccPrivateKeyToDer: %d", n)
	}
	k, err := ParseECPrivateKeyDER(der[:n])
	if err != nil {
		t.Fatalf("ParseECPrivateKeyDER(private-only P-256): %v", err)
	}
	defer k.Free()
	if alg := k.Algorithm(); alg != AlgECDSAP256 {
		t.Fatalf("Algorithm() = %d, want %d", alg, AlgECDSAP256)
	}

	k2, err := NewEmptyEccKey()
	if err != nil {
		t.Fatalf("NewEmptyEccKey: %v", err)
	}
	defer k2.Free()
	idx := 0
	if ret := wolfSSL.Wc_EccPrivateKeyDecode(der[:n], &idx, k2.Raw(), n); ret != 0 {
		t.Fatalf("Wc_EccPrivateKeyDecode: %d", ret)
	}
	k2.MarkLive()
	if alg := k2.Algorithm(); alg != AlgECDSAP256 {
		t.Fatalf("MarkLive on private-only P-256: Algorithm() = %d, want %d", alg, AlgECDSAP256)
	}
}

func TestEccKeyConcurrentSignAndFree(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 25; j++ {
				sig, err := SignDigest(k, digest)
				if err == nil && len(sig) == 0 {
					t.Error("SignDigest returned an empty signature")
				}
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			k.Free()
		}()
	}
	close(start)
	wg.Wait()
	if k.IsLive() {
		t.Fatal("key still live after Free")
	}
	if _, err := SignDigest(k, digest); err == nil {
		t.Fatal("SignDigest succeeded on a freed key")
	}
}

func TestLockEccKeysSerializesDirectUse(t *testing.T) {
	k1, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k1.Free()
	k2, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k2.Free()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			signer, other := k1, k2
			if i%2 == 1 {
				signer, other = k2, k1
			}
			for j := 0; j < 10; j++ {
				unlock := LockEccKeys(signer, other, signer)
				if signer.CKeyPtr() != nil && other.CKeyPtr() != nil {
					sig := make([]byte, wolfSSL.ECC_MAX_SIG_SIZE)
					sigLen := len(sig)
					if ret := wolfSSL.Wc_ecc_sign_hash(digest, len(digest), sig, &sigLen,
						signer.Rng(), signer.Raw()); ret != 0 {
						t.Errorf("Wc_ecc_sign_hash: %d", ret)
					}
				}
				unlock()
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		k1.Free()
		k2.Free()
	}()
	close(start)
	wg.Wait()
	if k1.CKeyPtr() != nil || k2.CKeyPtr() != nil {
		t.Fatal("CKeyPtr non-nil after Free")
	}
}

// holdFirstAcquire makes the first locked operation wait inside its key lock
// until release is closed; entered is closed once it is waiting.
func holdFirstAcquire(t *testing.T) (entered, release chan struct{}) {
	entered = make(chan struct{})
	release = make(chan struct{})
	var once sync.Once
	testHookAcquired = func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	t.Cleanup(func() { testHookAcquired = nil })
	return entered, release
}

// assertBlocked fails if done closes before release is closed, then releases
// and waits for done.
func assertBlocked(t *testing.T, done <-chan struct{}, release chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s returned while an operation held the key", what)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
}

func TestEccKeyFreeWaitsForInFlightSign(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	entered, release := holdFirstAcquire(t)
	signErr := make(chan error, 1)
	go func() {
		sig, err := SignDigest(k, digest)
		if err == nil && len(sig) == 0 {
			err = errors.New("empty signature")
		}
		signErr <- err
	}()
	<-entered
	freed := make(chan struct{})
	go func() {
		k.Free()
		close(freed)
	}()
	assertBlocked(t, freed, release, "Free")
	if err := <-signErr; err != nil {
		t.Fatalf("in-flight SignDigest: %v", err)
	}
	if k.IsLive() || k.Algorithm() != AlgUnknown || k.CKeyPtr() != nil {
		t.Fatal("freed key still reports live state")
	}
	var nilKey *EccKey
	if nilKey.Algorithm() != AlgUnknown || nilKey.IsLive() {
		t.Fatal("nil key reports live state")
	}
}

func TestEccKeyMarkLiveAfterFreeStaysDead(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	k.Free()
	k.MarkLive()
	if k.IsLive() || k.CKeyPtr() != nil {
		t.Fatal("MarkLive revived a freed key")
	}
	if _, err := MarshalSEC1DER(k); err == nil {
		t.Fatal("MarshalSEC1DER accepted a freed key")
	}
}

func TestEccKeyAlgorithmDerivesOnlyMissingPublicPoint(t *testing.T) {
	var empty wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&empty); ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer wolfSSL.Wc_ecc_free(&empty)
	if alg, ret := eccKeyAlgorithm(&empty); alg != AlgUnknown || ret >= 0 {
		t.Fatalf("eccKeyAlgorithm(empty key) = (%d, %d), want (AlgUnknown, <0)", alg, ret)
	}

	_, pub := eccTestKeyDER(t, 32)
	var pubKey wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&pubKey); ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer wolfSSL.Wc_ecc_free(&pubKey)
	idx := 0
	if ret := wolfSSL.Wc_EccPublicKeyDecode(pub, &idx, &pubKey, len(pub)); ret != 0 {
		t.Fatalf("Wc_EccPublicKeyDecode: %d", ret)
	}
	if alg, ret := eccKeyAlgorithm(&pubKey); alg != AlgECDSAP256 || ret != 0 {
		t.Fatalf("eccKeyAlgorithm(P-256 public key) = (%d, %d), want (AlgECDSAP256, 0)", alg, ret)
	}
}

// recordZeroBytes replaces zeroBytes for the duration of the test and returns
// a function reporting every buffer passed to it.
func recordZeroBytes(t *testing.T) func() [][]byte {
	var mu sync.Mutex
	var wiped [][]byte
	orig := zeroBytes
	zeroBytes = func(b []byte) {
		orig(b)
		mu.Lock()
		wiped = append(wiped, b)
		mu.Unlock()
	}
	t.Cleanup(func() { zeroBytes = orig })
	return func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return wiped
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestParseECPrivateKeyPEMWipesDER(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()
	for _, marshal := range []func(*EccKey) ([]byte, error){MarshalSEC1PEM, MarshalPKCS8PEM} {
		p, err := marshal(k)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		wiped := recordZeroBytes(t)
		k2, err := ParseECPrivateKeyPEM(p)
		if err != nil {
			t.Fatalf("ParseECPrivateKeyPEM: %v", err)
		}
		k2.Free()
		found := false
		for _, b := range wiped() {
			if len(b) == len(p) && allZero(b) {
				found = true
			}
		}
		if !found {
			t.Fatal("decoded private-key DER buffer was not wiped")
		}
	}
}
