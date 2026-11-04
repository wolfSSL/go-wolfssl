/* fuzz_test.go
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// fuzzSeedECKeys returns SEC 1 and PKCS #8 DER for a P-256 and a P-384 key.
func fuzzSeedECKeys(f *testing.F) (sec1, pkcs8 [][]byte) {
	f.Helper()
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			f.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			f.Fatal(err)
		}
		p8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			f.Fatal(err)
		}
		sec1 = append(sec1, der)
		pkcs8 = append(pkcs8, p8)
	}
	return sec1, pkcs8
}

func FuzzParseECPrivateKeyDER(f *testing.F) {
	sec1, _ := fuzzSeedECKeys(f)
	for _, der := range sec1 {
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		if k, err := ParseECPrivateKeyDER(der); err == nil {
			k.Free()
		}
	})
}

func FuzzParsePKCS8ECPrivateKeyDER(f *testing.F) {
	_, pkcs8 := fuzzSeedECKeys(f)
	for _, der := range pkcs8 {
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		if k, err := ParsePKCS8ECPrivateKeyDER(der); err == nil {
			k.Free()
		}
	})
}

func FuzzParseECPrivateKeyPEM(f *testing.F) {
	sec1, pkcs8 := fuzzSeedECKeys(f)
	for _, der := range sec1 {
		f.Add(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}
	for _, der := range pkcs8 {
		f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		if k, err := ParseECPrivateKeyPEM(p); err == nil {
			k.Free()
		}
	})
}
