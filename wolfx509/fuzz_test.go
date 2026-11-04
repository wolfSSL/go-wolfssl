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

package wolfx509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fuzzSeedCerts returns the DER of every certificate in examples/certs.
func fuzzSeedCerts(f *testing.F) [][]byte {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("..", "examples", "certs", "*.pem"))
	if err != nil {
		f.Fatal(err)
	}
	var ders [][]byte
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
			if block.Type == "CERTIFICATE" {
				ders = append(ders, block.Bytes)
			}
		}
	}
	if len(ders) == 0 {
		f.Fatal("no seed certificates found")
	}
	return ders
}

func FuzzParseCertificate(f *testing.F) {
	for _, der := range fuzzSeedCerts(f) {
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		c, err := ParseCertificate(der)
		if err != nil {
			return
		}
		defer c.Free()
		again, err := ParseCertificate(c.Raw)
		if err != nil {
			t.Fatalf("Raw of a parsed certificate does not parse: %v", err)
		}
		defer again.Free()
		if !again.Equal(c) {
			t.Fatal("reparsing Raw gave a different certificate")
		}
	})
}

func FuzzParseCertificates(f *testing.F) {
	seeds := fuzzSeedCerts(f)
	for _, der := range seeds {
		f.Add(der)
	}
	f.Add(bytes.Join(seeds, nil))
	f.Fuzz(func(t *testing.T, der []byte) {
		certs, err := ParseCertificates(der)
		if err != nil {
			return
		}
		for _, c := range certs {
			c.Free()
		}
	})
}

// fuzzFreshChain returns a CA and a www.wolfssl.com leaf it signed, valid
// around now, so FuzzVerify keeps a passing seed after the fixtures expire.
func fuzzFreshChain(f *testing.F) (caDER, leafDER []byte) {
	f.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fuzz CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(7 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if caDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey); err != nil {
		f.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		f.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "www.wolfssl.com"},
		DNSNames:     []string{"www.wolfssl.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		f.Fatal(err)
	}
	return caDER, leafDER
}

func FuzzVerify(f *testing.F) {
	caDER, leafDER := fuzzFreshChain(f)
	seeds := append(fuzzSeedCerts(f), caDER)
	for _, der := range seeds {
		f.Add(der)
	}
	f.Add(leafDER)
	f.Fuzz(func(t *testing.T, der []byte) {
		c, err := ParseCertificate(der)
		if err != nil {
			return
		}
		defer c.Free()
		roots := NewCertPool()
		defer roots.Free()
		for _, s := range seeds {
			if root, err := ParseCertificate(s); err == nil {
				roots.AddCert(root)
				root.Free()
			}
		}
		chains, err := c.Verify(VerifyOptions{Roots: roots, DNSName: "www.wolfssl.com"})
		if err == nil && (len(chains) == 0 || len(chains[0]) == 0) {
			t.Fatal("Verify succeeded without returning a chain")
		}
		if err != nil && bytes.Equal(der, leafDER) {
			t.Fatalf("the fresh leaf did not verify: %v", err)
		}
		for _, chain := range chains {
			for _, cert := range chain {
				if cert != c {
					cert.Free()
				}
			}
		}
	})
}
