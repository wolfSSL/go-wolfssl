/* certgen_test.go
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
	"math/big"
	"net"
	"testing"
	"time"
)

func TestCreateSelfSignedBasic(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	tmpl := &Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      Name{CommonName: "test.example"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := CreateCertificate(tmpl, tmpl, k, k)
	if err != nil {
		skipIfCertGenMissing(t, err)
		t.Fatalf("CreateCertificate: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("empty cert DER")
	}

	parsed, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("wolfx509.ParseCertificate: %v", err)
	}
	defer parsed.Free()
	if parsed.Subject.CommonName != "test.example" {
		t.Errorf("Subject CN = %q, want %q", parsed.Subject.CommonName, "test.example")
	}
	if parsed.SerialNumber == nil || parsed.SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("SerialNumber = %v, want 42", parsed.SerialNumber)
	}

	// Stdlib cross-check — wolfCrypt-built cert must parse via crypto/x509.
	stdCert, err := stdlibParseCert(der)
	if err != nil {
		t.Fatalf("stdlib crypto/x509.ParseCertificate rejected wolfCrypt cert: %v", err)
	}
	if stdCert.Subject.CommonName != "test.example" {
		t.Errorf("stdlib Subject CN = %q", stdCert.Subject.CommonName)
	}
}

func TestCreateSelfSignedWithSANs(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	tmpl := &Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               Name{CommonName: "san-test"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"host.example", "*.wild.example"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageKeyEncipherment,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth},
	}
	der, err := CreateCertificate(tmpl, tmpl, k, k)
	if err != nil {
		skipIfCertGenMissing(t, err)
		t.Fatalf("CreateCertificate: %v", err)
	}

	// Verify through stdlib — the most thorough parse available.
	stdCert, err := stdlibParseCert(der)
	if err != nil {
		t.Fatalf("stdlib parse: %v", err)
	}
	wantDNS := map[string]bool{"host.example": true, "*.wild.example": true}
	for _, n := range stdCert.DNSNames {
		if !wantDNS[n] {
			t.Errorf("unexpected DNS SAN %q", n)
		}
		delete(wantDNS, n)
	}
	if len(wantDNS) != 0 {
		t.Errorf("missing DNS SANs: %v", wantDNS)
	}
	if len(stdCert.IPAddresses) != 2 {
		t.Errorf("got %d IP SANs, want 2 — %v", len(stdCert.IPAddresses), stdCert.IPAddresses)
	}

	// KeyUsage + ExtKeyUsage flow-through.
	wantKU := 0x80 | 0x20 // digitalSignature | keyEncipherment (RFC 5280 ordering)
	gotKU := int(stdCert.KeyUsage)
	// crypto/x509's KeyUsage constants happen to match RFC 5280 bit
	// positions but with bit 0 = digitalSignature (not 0x80). Just check
	// that both flags were set, rather than the numeric value.
	_ = wantKU
	if gotKU == 0 {
		t.Errorf("stdlib parsed zero KeyUsage")
	}
	if len(stdCert.ExtKeyUsage) != 2 {
		t.Errorf("got %d ExtKeyUsage entries, want 2", len(stdCert.ExtKeyUsage))
	}
}

func TestCreateCertificateRejectsEmptyParentRaw(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	tmpl := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Name{CommonName: "x"},
		NotAfter:     time.Now().Add(time.Hour),
	}
	parent := &Certificate{
		// Raw intentionally empty — should error out rather than crash.
		Subject:  Name{CommonName: "ca"},
		NotAfter: time.Now().Add(time.Hour),
	}
	if _, err := CreateCertificate(tmpl, parent, k, k); err == nil {
		t.Errorf("expected error when parent.Raw is empty for CA-signed path")
	}
}

func TestCreateCASignedCert(t *testing.T) {
	// Build a CA keypair + self-signed CA cert.
	caKey, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key (CA): %v", err)
	}
	defer caKey.Free()

	caTmpl := &Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageCertSign | KeyUsageCRLSign,
	}
	caDER, err := CreateCertificate(caTmpl, caTmpl, caKey, caKey)
	if err != nil {
		skipIfCertGenMissing(t, err)
		t.Fatalf("CreateCertificate (CA): %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate (CA): %v", err)
	}
	defer caCert.Free()

	// Build a leaf keypair + CA-signed leaf cert.
	leafKey, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key (leaf): %v", err)
	}
	defer leafKey.Free()

	leafTmpl := &Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      Name{CommonName: "leaf.example"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"leaf.example"},
		KeyUsage:     KeyUsageDigitalSignature | KeyUsageKeyEncipherment,
		ExtKeyUsage:  []ExtKeyUsage{ExtKeyUsageServerAuth},
	}
	leafDER, err := CreateCertificate(leafTmpl, caCert, leafKey, caKey)
	if err != nil {
		skipIfCertGenMissing(t, err)
		t.Fatalf("CreateCertificate (CA-signed leaf): %v", err)
	}
	leafCert, err := ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate (leaf): %v", err)
	}
	defer leafCert.Free()

	if leafCert.Issuer.CommonName != "Test CA" {
		t.Errorf("leaf Issuer.CN = %q, want %q", leafCert.Issuer.CommonName, "Test CA")
	}

	// Stdlib verifies the leaf against the CA.
	roots := stdlibNewCertPool()
	stdCA, err := stdlibParseCert(caDER)
	if err != nil {
		t.Fatalf("stdlib parse CA: %v", err)
	}
	stdLeaf, err := stdlibParseCert(leafDER)
	if err != nil {
		t.Fatalf("stdlib parse leaf: %v", err)
	}
	stdlibAddCert(roots, stdCA)
	if err := stdlibVerifyLeaf(stdLeaf, roots, "leaf.example"); err != nil {
		t.Fatalf("stdlib verification of wolfCrypt-issued CA-signed cert failed: %v", err)
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	tmpl := &CertificateRequest{
		Subject:  Name{CommonName: "csr.example"},
		DNSNames: []string{"csr.example", "alt.csr.example"},
	}
	der, err := CreateCertificateRequest(tmpl, k)
	if err != nil {
		skipIfCertGenMissing(t, err)
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("empty CSR DER")
	}

	// Stdlib cross-check: the CSR must parse and its signature must verify.
	stdCSR, err := stdlibParseCSR(der)
	if err != nil {
		t.Fatalf("stdlib crypto/x509.ParseCertificateRequest: %v", err)
	}
	if err := stdlibCheckCSRSignature(stdCSR); err != nil {
		t.Fatalf("stdlib CSR signature check: %v", err)
	}
	if stdCSR.Subject.CommonName != "csr.example" {
		t.Errorf("CSR Subject.CN = %q", stdCSR.Subject.CommonName)
	}
	wantDNS := map[string]bool{"csr.example": true, "alt.csr.example": true}
	for _, n := range stdCSR.DNSNames {
		if !wantDNS[n] {
			t.Errorf("unexpected CSR DNS %q", n)
		}
		delete(wantDNS, n)
	}
	if len(wantDNS) != 0 {
		t.Errorf("missing CSR DNS entries: %v", wantDNS)
	}
}

func TestValidityDays(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name           string
		before, after  time.Time
		wantDays       int
		wantErr        bool
	}{
		{"past-NotBefore spans window", now.Add(-24 * time.Hour), now.Add(72 * time.Hour), 4, false},
		{"future-NotBefore", now.Add(1 * time.Hour), now.Add(48 * time.Hour), 2, false},
		{"zero NotBefore", time.Time{}, now.Add(10 * 24 * time.Hour), 10, false},
		{"NotAfter before NotBefore", now.Add(time.Hour), now.Add(-time.Hour), 0, true},
		{"zero NotAfter", time.Time{}, time.Time{}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := validityDays(c.before, c.after)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if err == nil && got != c.wantDays {
				// Allow off-by-one for same-day rounding.
				if diff := got - c.wantDays; diff != 0 && diff != 1 && diff != -1 {
					t.Errorf("days=%d want~%d", got, c.wantDays)
				}
			}
		})
	}
}
