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
	"runtime"
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

func TestParsedPublicKeyOutlivesCertificate(t *testing.T) {
	der := mintCert(t, "pk-lifetime.example")

	freed, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pk := freed.DetachPublicKey()
	defer FreeKey(pk)
	freed.Free()
	if freed.PublicKey != nil {
		t.Error("Free left PublicKey attached to the Certificate")
	}
	if _, _, err := handles.PublicRawXY(pk.(*handles.EccKey)); err != nil {
		t.Errorf("detached PublicKey unusable after Certificate.Free: %v", err)
	}

	collected, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pk2 := collected.PublicKey
	defer FreeKey(pk2)
	runtime.SetFinalizer(collected, nil)
	collected.finalize()
	if _, _, err := handles.PublicRawXY(pk2.(*handles.EccKey)); err != nil {
		t.Errorf("PublicKey unusable after its Certificate was collected: %v", err)
	}

	caKey, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer caKey.Free()
	tmpl := &Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      Name{CommonName: "self"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	caDER, err := CreateCertificate(tmpl, tmpl, caKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	ca, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}
	defer ca.Free()
	leafTmpl := &Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := CreateCertificate(leafTmpl, ca, pk, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate with a key detached from a freed Certificate: %v", err)
	}
	leaf, err := ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate(leaf): %v", err)
	}
	defer leaf.Free()
	if gotX, _, err := leaf.PublicECCRawXY(); err != nil {
		t.Errorf("leaf PublicECCRawXY: %v", err)
	} else if wantX, _, _ := handles.PublicRawXY(pk.(*handles.EccKey)); !bytes.Equal(gotX, wantX) {
		t.Error("leaf public key does not match the parsed key")
	}
}

func TestCertificateFreeReleasesOwnedPublicKey(t *testing.T) {
	c, err := ParseCertificate(mintCert(t, "freekey.example"))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pk := c.PublicKey
	c.Free()
	if pk.(*handles.EccKey).IsLive() {
		t.Error("Certificate.Free left its parsed PublicKey live")
	}

	caKey, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer caKey.Free()
	freedKey, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	freedKey.Free()
	tmpl := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Name{CommonName: "freed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	for name, keys := range map[string][2]KeyHandle{
		"freed parsed public key": {pk, caKey},
		"freed public key":        {freedKey, caKey},
		"freed signer":            {caKey, freedKey},
	} {
		if _, err := CreateCertificate(tmpl, tmpl, keys[0], keys[1]); err == nil {
			t.Errorf("%s: CreateCertificate accepted it", name)
		}
	}
	if _, err := CreateCertificateRequest(&CertificateRequest{Subject: tmpl.Subject}, freedKey); err == nil {
		t.Error("CreateCertificateRequest accepted a freed key")
	}
}

func TestParseCertificatesFreesOnError(t *testing.T) {
	good := mintCert(t, "first.example")
	var parsed []*Certificate
	var keys []*handles.EccKey
	record := func(der []byte) (*Certificate, error) {
		c, err := ParseCertificate(der)
		if err == nil {
			parsed = append(parsed, c)
			keys = append(keys, c.PublicKey.(*handles.EccKey))
		}
		return c, err
	}

	bad := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	for name, input := range map[string][]byte{
		"unparseable second cert": append(append([]byte(nil), good...), bad...),
		"truncated second cert":   append(append([]byte(nil), good...), 0x30, 0x10, 0x00),
		"non-SEQUENCE trailer":    append(append([]byte(nil), good...), 0x04, 0x00),
	} {
		parsed, keys = nil, nil
		if _, err := parseCertificates(input, record); err == nil {
			t.Fatalf("%s: ParseCertificates succeeded", name)
		}
		if len(parsed) != 1 {
			t.Fatalf("%s: parsed %d certificates before the error, want 1", name, len(parsed))
		}
		if _, err := parsed[0].Verify(VerifyOptions{}); err != ErrInvalidCert {
			t.Errorf("%s: first certificate was not freed (Verify err = %v)", name, err)
		}
		if keys[0].IsLive() {
			t.Errorf("%s: first certificate's PublicKey was not freed", name)
		}
	}
}
