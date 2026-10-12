/* x509_test.go
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// loadPEM reads a PEM file and returns the DER bytes of the first CERTIFICATE block.
func loadPEM(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s: no CERTIFICATE PEM block", path)
	}
	return block.Bytes
}

// rawPEM returns the raw PEM bytes, for CertPool.AppendCertsFromPEM.
func rawPEM(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// certsDir resolves the go-wolfssl examples/certs directory relative to this
// test file.
func certsDir(t *testing.T) string {
	t.Helper()
	// tests run with cwd = the package dir; certs live one level up.
	return filepath.Join("..", "examples", "certs")
}

func TestParseCertificateDER(t *testing.T) {
	der := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	if !strings.Contains(cert.Subject.CommonName, "wolfssl.com") {
		t.Errorf("Subject.CommonName = %q, want containing wolfssl.com", cert.Subject.CommonName)
	}
	if cert.Issuer.String() == "" {
		t.Errorf("Issuer.String() returned empty")
	}
	if cert.NotBefore.IsZero() {
		t.Errorf("NotBefore is zero; parse failed")
	}
	if cert.NotAfter.IsZero() {
		t.Errorf("NotAfter is zero; parse failed")
	}
	if !cert.NotBefore.Before(cert.NotAfter) {
		t.Errorf("NotBefore %v not before NotAfter %v", cert.NotBefore, cert.NotAfter)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() == 0 {
		t.Errorf("SerialNumber missing: %v", cert.SerialNumber)
	}
	if len(cert.Raw) != len(der) {
		t.Errorf("Raw len = %d, want %d", len(cert.Raw), len(der))
	}
}

func TestParseCertificateInvalid(t *testing.T) {
	_, err := ParseCertificate(nil)
	if err == nil {
		t.Fatal("expected error on nil DER")
	}
	_, err = ParseCertificate([]byte("not a cert"))
	if err == nil {
		t.Fatal("expected error on garbage DER")
	}
}

func TestVerifyWithRoot(t *testing.T) {
	caPEM := rawPEM(t, filepath.Join(certsDir(t), "ca-cert.pem"))
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))

	pool := NewCertPool()
	defer pool.Free()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM failed")
	}

	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	chains, err := cert.Verify(VerifyOptions{Roots: pool})
	if err != nil {
		t.Fatalf("Verify with correct CA failed: %v", err)
	}
	FreeChains(chains)
}

func TestVerifyWithoutRoot(t *testing.T) {
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	pool := NewCertPool() // empty
	defer pool.Free()

	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	_, err = cert.Verify(VerifyOptions{Roots: pool})
	if err == nil {
		t.Fatal("Verify with empty pool should have failed")
	}
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("error = %v, want wrapping ErrVerifyFailed", err)
	}
}

// Test chain: ca-cert (self-signed root) → ca-int-cert → ca-int2-cert →
// client-int-cert (leaf).

// newPool returns a CertPool holding the named files from examples/certs.
func newPool(t *testing.T, files ...string) *CertPool {
	t.Helper()
	p := NewCertPool()
	t.Cleanup(p.Free)
	for _, f := range files {
		if !p.AppendCertsFromPEM(rawPEM(t, filepath.Join(certsDir(t), f))) {
			t.Fatalf("AppendCertsFromPEM(%s) failed", f)
		}
	}
	return p
}

// parseCert parses the named file from examples/certs.
func parseCert(t *testing.T, file string) *Certificate {
	t.Helper()
	c, err := ParseCertificate(loadPEM(t, filepath.Join(certsDir(t), file)))
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", file, err)
	}
	t.Cleanup(c.Free)
	return c
}

func TestVerifyChains(t *testing.T) {
	leaf := parseCert(t, "client-int-cert.pem")
	tests := []struct {
		name          string
		roots         *CertPool
		intermediates *CertPool
		wantOK        bool
	}{
		{"full chain", newPool(t, "ca-cert.pem"), newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem"), true},
		{"missing ca-int-cert", newPool(t, "ca-cert.pem"), newPool(t, "ca-int2-cert.pem"), false},
		// Only self-signed certs in Roots are trusted.
		{"non-self-signed root", newPool(t, "ca-int2-cert.pem"), nil, false},
		// Intermediates are never trusted on their own.
		{"no roots", newPool(t), newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem"), false},
	}
	for _, tt := range tests {
		chains, err := leaf.Verify(VerifyOptions{Roots: tt.roots, Intermediates: tt.intermediates})
		FreeChains(chains)
		if (err == nil) != tt.wantOK {
			t.Errorf("%s: err = %v, want ok = %v", tt.name, err, tt.wantOK)
		}
	}
}

// wolfSSL changes the store during verification, so Verify must serialize
// calls on a shared Roots pool. Run passing and failing verifications
// concurrently: if one leaked state into another, results would flip.
func TestVerifyConcurrent(t *testing.T) {
	leaf := parseCert(t, "client-int-cert.pem")
	roots := newPool(t, "ca-cert.pem")
	all := newPool(t, "ca-cert.pem", "ca-int-cert.pem", "ca-int2-cert.pem")
	good := VerifyOptions{Roots: roots, Intermediates: newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem")}
	bad := VerifyOptions{Roots: roots, Intermediates: newPool(t, "ca-int2-cert.pem")}
	samePool := VerifyOptions{Roots: all, Intermediates: all}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			chains, err := leaf.Verify(good)
			if err != nil {
				t.Errorf("good chain failed: %v", err)
			}
			FreeChains(chains)
		}()
		go func() {
			defer wg.Done()
			if _, err := leaf.Verify(bad); err == nil {
				t.Error("incomplete chain verified")
			}
		}()
		go func() {
			defer wg.Done()
			chains, err := leaf.Verify(samePool)
			if err != nil {
				t.Errorf("same pool as Roots and Intermediates failed: %v", err)
			}
			FreeChains(chains)
		}()
	}
	wg.Wait()
}

func TestVerifyNilRoots(t *testing.T) {
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	_, err = cert.Verify(VerifyOptions{}) // nil Roots
	if err == nil {
		t.Fatal("Verify with nil Roots should have failed")
	}
}

func TestVerifyHostname(t *testing.T) {
	// server-cert.pem has SAN: DNS:example.com, IP:127.0.0.1; CN: www.wolfssl.com
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	// Matches SAN
	if err := cert.VerifyHostname("example.com"); err != nil {
		t.Errorf("VerifyHostname(example.com): %v", err)
	}
	// Does not match
	if err := cert.VerifyHostname("not-the-host.example.org"); err == nil {
		t.Error("VerifyHostname should have failed for unrelated host")
	}
}

func TestCertificateSurvivesFree(t *testing.T) {
	der := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Capture fields before Free.
	cn := cert.Subject.CommonName
	notAfter := cert.NotAfter
	rawLen := len(cert.Raw)

	cert.Free()

	// Go-memory fields must still be valid.
	if cert.Subject.CommonName != cn {
		t.Error("Subject.CommonName mutated after Free")
	}
	if !cert.NotAfter.Equal(notAfter) {
		t.Error("NotAfter mutated after Free")
	}
	if len(cert.Raw) != rawLen {
		t.Error("Raw mutated after Free")
	}

	// Verify and VerifyHostname must refuse to dereference the freed pointer.
	if _, err := cert.Verify(VerifyOptions{Roots: NewCertPool()}); err == nil {
		t.Error("Verify after Free should have failed")
	}
	if err := cert.VerifyHostname("example.com"); err == nil {
		t.Error("VerifyHostname after Free should have failed")
	}

	// Double Free is safe.
	cert.Free()
}

func TestConcurrentParse(t *testing.T) {
	der := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			c, err := ParseCertificate(der)
			if err != nil {
				errs <- err
				return
			}
			_ = c.Subject.CommonName
			c.Free()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent parse: %v", err)
	}
}

func TestParseCertificateExtensionsMatchStdlib(t *testing.T) {
	ders := map[string][]byte{}
	for _, f := range []string{"server-cert.pem", "client-int-cert.pem", "ca-int-cert.pem"} {
		ders[f] = loadPEM(t, filepath.Join(certsDir(t), f))
	}
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()
	tmpl := &Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               Name{CommonName: "ext.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"a.example", "b.example"},
		EmailAddresses:        []string{"x@example.com"},
		IPAddresses:           []net.IP{net.IPv4(10, 0, 0, 1), net.ParseIP("2001:db8::1")},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageKeyAgreement,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageCodeSigning},
	}
	if ders["generated"], err = CreateCertificate(tmpl, tmpl, k, k); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	for name, der := range ders {
		c, err := ParseCertificate(der)
		if err != nil {
			t.Fatalf("%s: ParseCertificate: %v", name, err)
		}
		defer c.Free()
		s, err := stdlibParseCert(der)
		if err != nil {
			t.Fatalf("%s: stdlib parse: %v", name, err)
		}
		if c.BasicConstraintsValid != s.BasicConstraintsValid || c.IsCA != s.IsCA {
			t.Errorf("%s: BasicConstraintsValid/IsCA = %v/%v, want %v/%v", name,
				c.BasicConstraintsValid, c.IsCA, s.BasicConstraintsValid, s.IsCA)
		}
		if c.KeyUsage != KeyUsage(s.KeyUsage) {
			t.Errorf("%s: KeyUsage = %#x, want %#x", name, c.KeyUsage, s.KeyUsage)
		}
		var wantEKU []ExtKeyUsage
		for _, u := range s.ExtKeyUsage {
			wantEKU = append(wantEKU, ExtKeyUsage(u))
		}
		if !sameEKUs(c.ExtKeyUsage, wantEKU) {
			t.Errorf("%s: ExtKeyUsage = %v, want %v", name, c.ExtKeyUsage, wantEKU)
		}
		if strings.Join(c.DNSNames, ",") != strings.Join(s.DNSNames, ",") {
			t.Errorf("%s: DNSNames = %q, want %q", name, c.DNSNames, s.DNSNames)
		}
		if strings.Join(c.EmailAddresses, ",") != strings.Join(s.EmailAddresses, ",") {
			t.Errorf("%s: EmailAddresses = %q, want %q", name, c.EmailAddresses, s.EmailAddresses)
		}
		if len(c.IPAddresses) != len(s.IPAddresses) {
			t.Errorf("%s: IPAddresses = %v, want %v", name, c.IPAddresses, s.IPAddresses)
		} else {
			for i := range s.IPAddresses {
				if !c.IPAddresses[i].Equal(s.IPAddresses[i]) {
					t.Errorf("%s: IPAddresses = %v, want %v", name, c.IPAddresses, s.IPAddresses)
					break
				}
			}
		}
	}
}

func sameEKUs(a, b []ExtKeyUsage) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[ExtKeyUsage]int{}
	for _, u := range a {
		seen[u]++
	}
	for _, u := range b {
		if seen[u] == 0 {
			return false
		}
		seen[u]--
	}
	return true
}

func TestParseCertificateExtKeyUsageAllPurposes(t *testing.T) {
	unknown := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}
	der, err := stdlibCertWithEKUs(unknown)
	if err != nil {
		t.Fatalf("stdlibCertWithEKUs: %v", err)
	}
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer c.Free()
	s, err := stdlibParseCert(der)
	if err != nil {
		t.Fatalf("stdlib parse: %v", err)
	}
	if len(c.ExtKeyUsage) != len(s.ExtKeyUsage) {
		t.Fatalf("ExtKeyUsage = %v, want %v", c.ExtKeyUsage, s.ExtKeyUsage)
	}
	for i := range s.ExtKeyUsage {
		if c.ExtKeyUsage[i] != ExtKeyUsage(s.ExtKeyUsage[i]) {
			t.Fatalf("ExtKeyUsage = %v, want %v", c.ExtKeyUsage, s.ExtKeyUsage)
		}
	}
	if len(c.UnknownExtKeyUsage) != 1 || !c.UnknownExtKeyUsage[0].Equal(unknown[0]) {
		t.Errorf("UnknownExtKeyUsage = %v, want %v", c.UnknownExtKeyUsage, unknown)
	}
}

func TestParseCertificateSANTypesAndOrder(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://uri.example/path")
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "order"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		DNSNames:       []string{"d1.example", "d2.example"},
		EmailAddresses: []string{"a@example.com", "b@example.com", "c@example.com"},
		IPAddresses:    []net.IP{net.IPv4(10, 0, 0, 1), net.ParseIP("2001:db8::1")},
		URIs:           []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := stdlibCertWithExtension(asn1.ObjectIdentifier{2, 5, 29, 17}, mustSAN(t,
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0, 0x05, 0x0c, 0x03, 'x', 'y', 'z'}},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("keep.example")},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{0x2a, 0x03, 0x04}},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: []byte{0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 'x', 'y', 'z'}},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("https://u.example/")},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("only@example.com")},
	))
	if err != nil {
		t.Fatal(err)
	}
	emailOnly, err := stdlibCertWithExtension(asn1.ObjectIdentifier{2, 5, 29, 17}, mustSAN(t,
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("first@example.com")},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("second@example.com")},
	))
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string][]byte{"mixed": der, "otherName+rid": other, "email only": emailOnly} {
		c, err := ParseCertificate(d)
		if err != nil {
			t.Fatalf("%s: ParseCertificate: %v", name, err)
		}
		s, _ := stdlibParseCert(d)
		if strings.Join(c.DNSNames, ",") != strings.Join(s.DNSNames, ",") ||
			strings.Join(c.EmailAddresses, ",") != strings.Join(s.EmailAddresses, ",") {
			t.Errorf("%s: DNS/email = %q %q, want %q %q", name, c.DNSNames, c.EmailAddresses, s.DNSNames, s.EmailAddresses)
		}
		c.Free()
	}
}

func mustSAN(t *testing.T, gns ...asn1.RawValue) []byte {
	t.Helper()
	b, err := asn1.Marshal(gns)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCreateCertificateRejectsUnencodableExtKeyUsage(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()
	for _, u := range []ExtKeyUsage{ExtKeyUsageIPSECEndSystem, ExtKeyUsageIPSECTunnel, ExtKeyUsageIPSECUser, ExtKeyUsage(99)} {
		tmpl := &Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      Name{CommonName: "eku"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			ExtKeyUsage:  []ExtKeyUsage{u},
		}
		if _, err := CreateCertificate(tmpl, tmpl, k, k); !errors.Is(err, ErrUnsupportedCreateMode) {
			t.Errorf("ExtKeyUsage %d: err = %v, want ErrUnsupportedCreateMode", u, err)
		}
	}
}

func TestParseCertificateRejectsEmptyExtKeyUsage(t *testing.T) {
	der, err := stdlibCertWithExtension(asn1.ObjectIdentifier{2, 5, 29, 37}, []byte{0x30, 0x00})
	if err != nil {
		t.Fatalf("stdlibCertWithExtension: %v", err)
	}
	if c, err := ParseCertificate(der); err == nil {
		t.Errorf("ParseCertificate accepted an empty extKeyUsage, ExtKeyUsage=%v", c.ExtKeyUsage)
		c.Free()
	}
}

func TestParseCertificateRejectsMalformedExtKeyUsage(t *testing.T) {
	oidEKU := asn1.ObjectIdentifier{2, 5, 29, 37}
	serverAuth := []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01}
	for name, exts := range map[string][]pkix.Extension{
		"wrong outer tag":   {{Id: oidEKU, Value: []byte{0x31, 0x03, 0x06, 0x01, 0x2b}}},
		"truncated":         {{Id: oidEKU, Value: serverAuth[:len(serverAuth)-2]}},
		"trailing data":     {{Id: oidEKU, Value: append(append([]byte(nil), serverAuth...), 0x00, 0x00)}},
		"non-OID element":   {{Id: oidEKU, Value: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}},
		"duplicate EKU ext": {{Id: oidEKU, Value: serverAuth}, {Id: oidEKU, Value: serverAuth}},
	} {
		der, err := stdlibCertWithExtensions(exts...)
		if err != nil {
			t.Fatalf("%s: stdlibCertWithExtensions: %v", name, err)
		}
		if c, err := ParseCertificate(der); err == nil {
			t.Errorf("%s: ParseCertificate accepted it, ExtKeyUsage=%v", name, c.ExtKeyUsage)
			c.Free()
		} else if !errors.Is(err, ErrInvalidCert) {
			t.Errorf("%s: err = %v, want ErrInvalidCert", name, err)
		}
	}
}

func TestParseCertificateRejectsMalformedSANs(t *testing.T) {
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}
	for name, gn := range map[string]asn1.RawValue{
		"dNSName with NUL":      {Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("good.example\x00evil.example")},
		"non-ASCII rfc822Name":  {Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("us\xc3\xa9r@example.com")},
		"empty dNSName":         {Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte{}},
		"empty rfc822Name":      {Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte{}},
		"5-byte iPAddress":      {Class: asn1.ClassContextSpecific, Tag: 7, Bytes: []byte{10, 0, 0, 1, 0}},
		"IPv4-mapped iPAddress": {Class: asn1.ClassContextSpecific, Tag: 7, Bytes: net.ParseIP("::ffff:192.0.2.1").To16()},
	} {
		value, err := asn1.Marshal([]asn1.RawValue{gn})
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		der, err := stdlibCertWithExtension(oidSAN, value)
		if err != nil {
			t.Fatalf("%s: stdlibCertWithExtension: %v", name, err)
		}
		if c, err := ParseCertificate(der); err == nil {
			t.Errorf("%s: ParseCertificate accepted it, DNSNames=%q EmailAddresses=%q IPAddresses=%v",
				name, c.DNSNames, c.EmailAddresses, c.IPAddresses)
			c.Free()
		}
	}
}

func TestVerifyReturnsVerifiedChain(t *testing.T) {
	leaf := parseCert(t, "client-int-cert.pem")
	roots := newPool(t, "ca-cert.pem")
	inter := newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem")
	chains, err := leaf.Verify(VerifyOptions{Roots: roots, Intermediates: inter})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := []string{"client-int-cert.pem", "ca-int2-cert.pem", "ca-int-cert.pem", "ca-cert.pem"}
	if len(chains) != 1 || len(chains[0]) != len(want) {
		t.Fatalf("got chains %v, want one chain of %d certificates", chains, len(want))
	}
	defer func() {
		for _, c := range chains[0] {
			c.Free()
		}
	}()
	if chains[0][0] == leaf {
		t.Error("chain reuses the caller's certificate instead of a caller-owned copy")
	}
	for i, f := range want {
		if !chains[0][i].Equal(parseCert(t, f)) {
			t.Errorf("chain[%d] is not %s", i, f)
		}
	}
}

func TestVerifyEnforcesExtKeyUsage(t *testing.T) {
	// client-int-cert.pem carries EKU clientAuth + emailProtection; the
	// ca-cert.pem root carries serverAuth + clientAuth.
	leaf := parseCert(t, "client-int-cert.pem")
	roots := newPool(t, "ca-cert.pem")
	inter := newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem")
	for _, tt := range []struct {
		usages []ExtKeyUsage
		wantOK bool
	}{
		{nil, true},
		{[]ExtKeyUsage{ExtKeyUsageServerAuth}, false},
		{[]ExtKeyUsage{ExtKeyUsageCodeSigning, ExtKeyUsageServerAuth}, false},
		{[]ExtKeyUsage{ExtKeyUsageClientAuth}, true},
		{[]ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageEmailProtection}, false},
		{[]ExtKeyUsage{ExtKeyUsageCodeSigning, ExtKeyUsageClientAuth}, true},
		{[]ExtKeyUsage{ExtKeyUsageAny}, true},
	} {
		chains, err := leaf.Verify(VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: tt.usages})
		FreeChains(chains)
		if (err == nil) != tt.wantOK {
			t.Errorf("KeyUsages=%v: err = %v, want ok = %v", tt.usages, err, tt.wantOK)
		}
		if err != nil && !errors.Is(err, ErrVerifyFailed) {
			t.Errorf("KeyUsages=%v: err = %v, want wrapping ErrVerifyFailed", tt.usages, err)
		}
	}
}

func TestVerifyExtKeyUsageTriesAlternativePath(t *testing.T) {
	newKey := func() KeyHandle {
		k, err := GenerateP256Key()
		if err != nil {
			t.Fatalf("GenerateP256Key: %v", err)
		}
		t.Cleanup(k.Free)
		return k
	}
	issue := func(tmpl, parent *Certificate, pub, signer KeyHandle) *Certificate {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
		der, err := CreateCertificate(tmpl, parent, pub, signer)
		if err != nil {
			t.Fatalf("CreateCertificate(%s): %v", tmpl.Subject.CommonName, err)
		}
		c, err := ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate(%s): %v", tmpl.Subject.CommonName, err)
		}
		t.Cleanup(c.Free)
		return c
	}
	rootKey, interKey, leafKey := newKey(), newKey(), newKey()
	rootTmpl := &Certificate{SerialNumber: big.NewInt(1), Subject: Name{CommonName: "alt-path root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign}
	root := issue(rootTmpl, rootTmpl, rootKey, rootKey)
	// Two certificates for the same intermediate name and key: one limited
	// to client auth, one unrestricted.
	clientOnly := issue(&Certificate{SerialNumber: big.NewInt(2), Subject: Name{CommonName: "alt-path CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign,
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageClientAuth}}, root, interKey, rootKey)
	open := issue(&Certificate{SerialNumber: big.NewInt(3), Subject: Name{CommonName: "alt-path CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign}, root, interKey, rootKey)
	leaf := issue(&Certificate{SerialNumber: big.NewInt(4), Subject: Name{CommonName: "alt-path leaf"},
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageServerAuth}}, clientOnly, leafKey, interKey)

	roots := NewCertPool()
	t.Cleanup(roots.Free)
	if err := roots.AddCert(root); err != nil {
		t.Fatalf("AddCert(root): %v", err)
	}
	for name, order := range map[string][]*Certificate{
		"restricted first": {clientOnly, open},
		"open first":       {open, clientOnly},
	} {
		inters := NewCertPool()
		t.Cleanup(inters.Free)
		for _, c := range order {
			if err := inters.AddCert(c); err != nil {
				t.Fatalf("AddCert: %v", err)
			}
		}
		chains, err := leaf.Verify(VerifyOptions{Roots: roots, Intermediates: inters,
			KeyUsages: []ExtKeyUsage{ExtKeyUsageServerAuth}})
		if err != nil {
			t.Errorf("%s: Verify: %v", name, err)
			continue
		}
		if len(chains[0]) != 3 || !chains[0][1].Equal(open) {
			t.Errorf("%s: chain does not go through the unrestricted intermediate", name)
		}
		if _, _, err := chains[0][1].PublicECCRawXY(); err != nil {
			t.Errorf("%s: returned chain certificate is not usable: %v", name, err)
		}
		FreeChains(chains)
	}

	// One pool as both Roots and Intermediates: the restricted CA must not
	// come back through the trust store once it is dropped.
	for name, order := range map[string][]*Certificate{
		"same pool, restricted first": {root, clientOnly, open},
		"same pool, open first":       {root, open, clientOnly},
	} {
		pool := NewCertPool()
		t.Cleanup(pool.Free)
		for _, c := range order {
			if err := pool.AddCert(c); err != nil {
				t.Fatalf("AddCert: %v", err)
			}
		}
		chains, err := leaf.Verify(VerifyOptions{Roots: pool, Intermediates: pool,
			KeyUsages: []ExtKeyUsage{ExtKeyUsageServerAuth}})
		if err != nil {
			t.Errorf("%s: Verify: %v", name, err)
			continue
		}
		if len(chains[0]) != 3 || !chains[0][1].Equal(open) {
			t.Errorf("%s: chain does not go through the unrestricted intermediate", name)
		}
		FreeChains(chains)
	}

	// More restricted alternatives than any small fixed retry budget.
	many := NewCertPool()
	t.Cleanup(many.Free)
	for i := 0; i < 20; i++ {
		c := issue(&Certificate{SerialNumber: big.NewInt(int64(100 + i)), Subject: Name{CommonName: "alt-path CA"},
			IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign,
			ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageClientAuth}}, root, interKey, rootKey)
		if err := many.AddCert(c); err != nil {
			t.Fatalf("AddCert: %v", err)
		}
	}
	if err := many.AddCert(open); err != nil {
		t.Fatalf("AddCert: %v", err)
	}
	chains, err := leaf.Verify(VerifyOptions{Roots: roots, Intermediates: many,
		KeyUsages: []ExtKeyUsage{ExtKeyUsageServerAuth}})
	if err != nil {
		t.Errorf("20 restricted alternatives: Verify: %v", err)
	}
	FreeChains(chains)

	only := NewCertPool()
	t.Cleanup(only.Free)
	if err := only.AddCert(clientOnly); err != nil {
		t.Fatalf("AddCert: %v", err)
	}
	_, err = leaf.Verify(VerifyOptions{Roots: roots, Intermediates: only,
		KeyUsages: []ExtKeyUsage{ExtKeyUsageServerAuth}})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("restricted path only: err = %v, want ErrVerifyFailed", err)
	}
	if errors.As(err, &UnknownAuthorityError{}) {
		t.Errorf("restricted path only: err = %v is reported as an unknown authority", err)
	}

	// Restrictions split across two CAs: leaf {server, client} <- caA
	// {client} <- caB {server} <- root leaves no common usage, but an
	// unrestricted caA certificate gives {server}.
	caBKey, caAKey, leaf2Key := newKey(), newKey(), newKey()
	caB := issue(&Certificate{SerialNumber: big.NewInt(5), Subject: Name{CommonName: "split CA B"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign,
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageServerAuth}}, root, caBKey, rootKey)
	caAClient := issue(&Certificate{SerialNumber: big.NewInt(6), Subject: Name{CommonName: "split CA A"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign,
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageClientAuth}}, caB, caAKey, caBKey)
	caAOpen := issue(&Certificate{SerialNumber: big.NewInt(7), Subject: Name{CommonName: "split CA A"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign}, caB, caAKey, caBKey)
	leaf2 := issue(&Certificate{SerialNumber: big.NewInt(8), Subject: Name{CommonName: "split leaf"},
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}}, caAClient, leaf2Key, caAKey)
	for name, order := range map[string][]*Certificate{
		"restricted first": {caB, caAClient, caAOpen},
		"open first":       {caB, caAOpen, caAClient},
	} {
		inters := NewCertPool()
		t.Cleanup(inters.Free)
		for _, c := range order {
			if err := inters.AddCert(c); err != nil {
				t.Fatalf("AddCert: %v", err)
			}
		}
		chains, err := leaf2.Verify(VerifyOptions{Roots: roots, Intermediates: inters,
			KeyUsages: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}})
		if err != nil {
			t.Errorf("split restrictions, %s: Verify: %v", name, err)
			continue
		}
		if len(chains[0]) != 4 || !chains[0][1].Equal(caAOpen) {
			t.Errorf("split restrictions, %s: chain does not go through the unrestricted CA", name)
		}
		FreeChains(chains)
	}
}

func TestVerifyExtKeyUsageKeepsIntermediateTrustAnchor(t *testing.T) {
	newKey := func() KeyHandle {
		k, err := GenerateP256Key()
		if err != nil {
			t.Fatalf("GenerateP256Key: %v", err)
		}
		t.Cleanup(k.Free)
		return k
	}
	issue := func(tmpl, parent *Certificate, pub, signer KeyHandle) *Certificate {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
		der, err := CreateCertificate(tmpl, parent, pub, signer)
		if err != nil {
			t.Fatalf("CreateCertificate(%s): %v", tmpl.Subject.CommonName, err)
		}
		c, err := ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate(%s): %v", tmpl.Subject.CommonName, err)
		}
		t.Cleanup(c.Free)
		return c
	}
	rootKey, interKey, leafKey := newKey(), newKey(), newKey()
	rootTmpl := &Certificate{SerialNumber: big.NewInt(1), Subject: Name{CommonName: "anchor test root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign}
	root := issue(rootTmpl, rootTmpl, rootKey, rootKey)
	inter := issue(&Certificate{SerialNumber: big.NewInt(2), Subject: Name{CommonName: "anchor test CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign}, root, interKey, rootKey)
	leaf := issue(&Certificate{SerialNumber: big.NewInt(3), Subject: Name{CommonName: "anchor test leaf"},
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageServerAuth}}, inter, leafKey, interKey)

	roots := NewCertPool()
	t.Cleanup(roots.Free)
	if err := roots.AddCert(inter); err != nil {
		t.Fatalf("AddCert(inter): %v", err)
	}
	// KeyUsages must not change which Roots are trusted.
	baseline, baseErr := leaf.Verify(VerifyOptions{Roots: roots})
	FreeChains(baseline)
	for _, usages := range [][]ExtKeyUsage{
		{ExtKeyUsageServerAuth},
		{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth},
	} {
		chains, err := leaf.Verify(VerifyOptions{Roots: roots, KeyUsages: usages})
		if (err == nil) != (baseErr == nil) {
			t.Errorf("KeyUsages=%v: err = %v, but without KeyUsages err = %v", usages, err, baseErr)
		}
		if err == nil && (len(chains[0]) != 2 || !chains[0][1].Equal(inter)) {
			t.Errorf("KeyUsages=%v: chain does not end at the trusted CA", usages)
		}
		FreeChains(chains)
	}
	_, err := leaf.Verify(VerifyOptions{Roots: roots, KeyUsages: []ExtKeyUsage{ExtKeyUsageClientAuth}})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("KeyUsages=[ClientAuth]: err = %v, want ErrVerifyFailed", err)
	}
}

func TestVerifyEnforcesIntermediateExtKeyUsage(t *testing.T) {
	newKey := func() KeyHandle {
		k, err := GenerateP256Key()
		if err != nil {
			t.Fatalf("GenerateP256Key: %v", err)
		}
		t.Cleanup(k.Free)
		return k
	}
	issue := func(tmpl, parent *Certificate, pub, signer KeyHandle) *Certificate {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
		der, err := CreateCertificate(tmpl, parent, pub, signer)
		if err != nil {
			t.Fatalf("CreateCertificate(%s): %v", tmpl.Subject.CommonName, err)
		}
		c, err := ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate(%s): %v", tmpl.Subject.CommonName, err)
		}
		t.Cleanup(c.Free)
		return c
	}
	rootKey, interKey, leafKey := newKey(), newKey(), newKey()
	rootTmpl := &Certificate{SerialNumber: big.NewInt(1), Subject: Name{CommonName: "eku root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign}
	root := issue(rootTmpl, rootTmpl, rootKey, rootKey)
	inter := issue(&Certificate{SerialNumber: big.NewInt(2), Subject: Name{CommonName: "eku client-only CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: KeyUsageCertSign,
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageClientAuth}}, root, interKey, rootKey)
	leaf := issue(&Certificate{SerialNumber: big.NewInt(3), Subject: Name{CommonName: "eku leaf"},
		ExtKeyUsage: []ExtKeyUsage{ExtKeyUsageServerAuth}}, inter, leafKey, interKey)

	roots, inters := NewCertPool(), NewCertPool()
	t.Cleanup(roots.Free)
	t.Cleanup(inters.Free)
	if err := roots.AddCert(root); err != nil {
		t.Fatalf("AddCert(root): %v", err)
	}
	if err := inters.AddCert(inter); err != nil {
		t.Fatalf("AddCert(inter): %v", err)
	}
	for _, tt := range []struct {
		usages []ExtKeyUsage
		wantOK bool
	}{
		{nil, true},
		{[]ExtKeyUsage{ExtKeyUsageAny}, true},
		{[]ExtKeyUsage{ExtKeyUsageServerAuth}, false},
		{[]ExtKeyUsage{ExtKeyUsageClientAuth}, false},
	} {
		chains, err := leaf.Verify(VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: tt.usages})
		FreeChains(chains)
		if (err == nil) != tt.wantOK {
			t.Errorf("KeyUsages=%v: err = %v, want ok = %v", tt.usages, err, tt.wantOK)
		}
	}
}
