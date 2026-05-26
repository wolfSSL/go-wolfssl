/* parsecerts_test.go
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
	"math/big"
	"testing"
	"time"

	"github.com/wolfssl/go-wolfssl/handles"
)

func TestParseCertificates_Single(t *testing.T) {
	der := mintCert(t, "single.example")

	certs, err := ParseCertificates(der)
	if err != nil {
		t.Fatalf("ParseCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "single.example" {
		t.Errorf("CN = %q", certs[0].Subject.CommonName)
	}
	certs[0].Free()
}

func TestParseCertificates_Chain(t *testing.T) {
	a := mintCert(t, "leaf.example")
	b := mintCert(t, "issuer.example")
	chain := append(append([]byte(nil), a...), b...)

	certs, err := ParseCertificates(chain)
	if err != nil {
		t.Fatalf("ParseCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if certs[0].Subject.CommonName != "leaf.example" {
		t.Errorf("first CN = %q", certs[0].Subject.CommonName)
	}
	if certs[1].Subject.CommonName != "issuer.example" {
		t.Errorf("second CN = %q", certs[1].Subject.CommonName)
	}
	certs[0].Free()
	certs[1].Free()
}

func TestPublicECCRawXY_RoundTripWithHandles(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	tmpl := &Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      Name{CommonName: "pub.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := CreateCertificate(tmpl, tmpl, k, k)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	parsed, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer parsed.Free()

	leafX, leafY, err := parsed.PublicECCRawXY()
	if err != nil {
		t.Fatalf("PublicECCRawXY (leaf): %v", err)
	}
	keyX, keyY, err := handles.PublicRawXY(k)
	if err != nil {
		t.Fatalf("PublicRawXY (key): %v", err)
	}
	if !bytes.Equal(leafX, keyX) {
		t.Errorf("X mismatch:\n leaf=%x\n  key=%x", leafX, keyX)
	}
	if !bytes.Equal(leafY, keyY) {
		t.Errorf("Y mismatch:\n leaf=%x\n  key=%x", leafY, keyY)
	}
}

func mintCert(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()
	tmpl := &Certificate{
		SerialNumber: big.NewInt(int64(time.Now().UnixNano() & 0x7fffffff)),
		Subject:      Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := CreateCertificate(tmpl, tmpl, k, k)
	if err != nil {
		t.Fatalf("CreateCertificate(%q): %v", cn, err)
	}
	return der
}
