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
	"encoding/pem"
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

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
