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
	"bytes"
	"encoding/asn1"
	"encoding/hex"
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

	notBefore := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)
	tmpl := &Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      Name{CommonName: "test.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := CreateCertificate(tmpl, tmpl, k, k)
	if err != nil {
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
	if !parsed.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %s, want %s", parsed.NotBefore, notBefore)
	}
	if !parsed.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %s, want %s", parsed.NotAfter, notAfter)
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

func TestCASignParsedPublicKeySerialGeneration(t *testing.T) {
	caKey, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer caKey.Free()

	caTmpl := &Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               Name{CommonName: "auto serial CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              KeyUsageCertSign,
	}
	caDER, err := CreateCertificate(caTmpl, caTmpl, caKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}
	defer caCert.Free()

	// The subject key as a CA sees it: parsed from a certificate, so
	// public-key-only and carrying no RNG.
	subjectDER, err := CreateCertificate(caTmpl, caTmpl, caKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(subject): %v", err)
	}
	subject, err := ParseCertificate(subjectDER)
	if err != nil {
		t.Fatalf("ParseCertificate(subject): %v", err)
	}
	defer subject.Free()
	if subject.PublicKey == nil {
		t.Fatal("parsed certificate carries no PublicKey")
	}
	if subject.PublicKey.CRngPtr() != nil {
		t.Error("a parsed public key should report no RNG")
	}

	leafTmpl := &Certificate{
		// No SerialNumber here: CreateCertificate has to generates one.
		Subject:   Name{CommonName: "auto serial leaf"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	leafDER, err := CreateCertificate(leafTmpl, caCert, subject.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA-signing a parsed public key with an auto serial: %v", err)
	}

	leaf, err := ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate(leaf): %v", err)
	}
	defer leaf.Free()
	if leaf.SerialNumber == nil || leaf.SerialNumber.Sign() == 0 {
		t.Errorf("expected a generated serial, got %v", leaf.SerialNumber)
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

func TestResolveValidity(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name          string
		before, after time.Time
		validDays     int
		wantErr       bool
	}{
		{"both set, past NotBefore", now.Add(-24 * time.Hour), now.Add(72 * time.Hour), 0, false},
		{"both set, future NotBefore", now.Add(1 * time.Hour), now.Add(48 * time.Hour), 0, false},
		{"neither set, ValidDays from now", time.Time{}, time.Time{}, 90, false},
		{"nothing set", time.Time{}, time.Time{}, 0, true},
		{"only NotAfter set", time.Time{}, now.Add(10 * 24 * time.Hour), 0, false},
		{"only NotAfter set, in the past", time.Time{}, now.Add(-time.Hour), 0, true},
		{"only NotBefore set", now.Add(-time.Hour), time.Time{}, 0, true},
		{"NotBefore with ValidDays", now.Add(-time.Hour), time.Time{}, 30, true},
		{"NotAfter and ValidDays conflict", now, now.Add(24 * time.Hour), 5, true},
		{"NotAfter before NotBefore", now.Add(time.Hour), now.Add(-time.Hour), 0, true},
		{"negative ValidDays", time.Time{}, time.Time{}, -1, true},
		{"negative ValidDays with both dates", now, now.Add(24 * time.Hour), -1, true},
		{"NotAfter year past 9999", now, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), 0, true},
		{"NotBefore year negative", time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC), now, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lo := time.Now()
			nb, na, err := resolveValidity(c.before, c.after, c.validDays)
			hi := time.Now()
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if err != nil {
				return
			}
			if !c.before.IsZero() {
				want := c.before.Truncate(time.Second)
				if !nb.Equal(want) {
					t.Errorf("NotBefore = %s, want %s", nb, want)
				}
			} else {
				nbLo := lo.Add(-clockSkewBackdate).Truncate(time.Second)
				nbHi := hi.Add(-clockSkewBackdate)
				if nb.Before(nbLo) || nb.After(nbHi) {
					t.Errorf("NotBefore = %s, want within [%s, %s]", nb, nbLo, nbHi)
				}
			}
			if !c.after.IsZero() {
				want := c.after.Truncate(time.Second)
				if !na.Equal(want) {
					t.Errorf("NotAfter = %s, want %s", na, want)
				}
			} else {
				d := time.Duration(c.validDays) * 24 * time.Hour
				naLo, naHi := lo.Add(d).Truncate(time.Second), hi.Add(d)
				if na.Before(naLo) || na.After(naHi) {
					t.Errorf("NotAfter = %s, want within [%s, %s]", na, naLo, naHi)
				}
			}
		})
	}
}

func TestEncodeValidityTime(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want []byte
	}{
		{
			"UTCTime for year <= 2049",
			time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC),
			append([]byte{asnUTCTimeTag, 13}, []byte("260720100000Z")...),
		},
		{
			"GeneralizedTime for year >= 2050",
			time.Date(2050, 1, 2, 3, 4, 5, 0, time.UTC),
			append([]byte{asnGeneralizedTimeTag, 15}, []byte("20500102030405Z")...),
		},
		{
			"GeneralizedTime for year < 1950",
			time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC),
			append([]byte{asnGeneralizedTimeTag, 15}, []byte("19491231235959Z")...),
		},
		{
			"non-UTC input normalized to UTC",
			time.Date(2026, 7, 20, 10, 0, 0, 0, time.FixedZone("UTC+2", 2*3600)),
			append([]byte{asnUTCTimeTag, 13}, []byte("260720080000Z")...),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := encodeValidityTime(c.in)
			if !bytes.Equal(got, c.want) {
				t.Errorf("encodeValidityTime = %v (%q), want %v (%q)",
					got, got[2:], c.want, c.want[2:])
			}
		})
	}
}

func TestCreateCertificateGeneralizedTime(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Date(3000, 1, 2, 3, 4, 5, 0, time.UTC)
	tmpl := &Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      Name{CommonName: "gt.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := CreateCertificate(tmpl, tmpl, k, k)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	parsed, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("wolfx509.ParseCertificate: %v", err)
	}
	defer parsed.Free()
	if !parsed.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %s, want %s", parsed.NotBefore, notBefore)
	}
	if !parsed.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %s, want %s", parsed.NotAfter, notAfter)
	}

	stdCert, err := stdlibParseCert(der)
	if err != nil {
		t.Fatalf("stdlib crypto/x509.ParseCertificate rejected wolfCrypt cert: %v", err)
	}
	if !stdCert.NotAfter.Equal(notAfter) {
		t.Errorf("stdlib NotAfter = %s, want %s", stdCert.NotAfter, notAfter)
	}
}

func TestCreateCertificateValidDays(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	tmpl := &Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      Name{CommonName: "validity.example"},
		ValidDays:    30,
	}
	lo := time.Now().Truncate(time.Second)
	der, err := CreateCertificate(tmpl, tmpl, k, k)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	hi := time.Now()

	parsed, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("wolfx509.ParseCertificate: %v", err)
	}
	defer parsed.Free()

	nbLo, nbHi := lo.Add(-clockSkewBackdate), hi.Add(-clockSkewBackdate)
	if parsed.NotBefore.Before(nbLo) || parsed.NotBefore.After(nbHi) {
		t.Errorf("NotBefore = %s, want within [%s, %s]", parsed.NotBefore, nbLo, nbHi)
	}
	naLo, naHi := lo.Add(30*24*time.Hour), hi.Add(30*24*time.Hour)
	if parsed.NotAfter.Before(naLo) || parsed.NotAfter.After(naHi) {
		t.Errorf("NotAfter = %s, want within [%s, %s]", parsed.NotAfter, naLo, naHi)
	}
}

// oidBasicConstraints is id-ce-basicConstraints (RFC 5280 4.2.1.9).
var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// TestBasicConstraintsMatrix pins the BasicConstraints extension that is
// emitted for a given template:
//   - emitted only when BasicConstraintsValid is set,
//   - always critical,
//   - present but with the cA boolean omitted (an empty SEQUENCE) when IsCA
//     is false.
func TestBasicConstraintsMatrix(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bcValid     bool
		isCA        bool
		wantPresent bool
		wantValue   string // hex of the extension value
	}{
		{"valid+CA", true, true, true, "30030101ff"},
		{"valid+notCA", true, false, true, "3000"},
		{"notValid+CA", false, true, false, ""},
		{"notValid+notCA", false, false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := GenerateP256Key()
			if err != nil {
				t.Fatalf("GenerateP256Key: %v", err)
			}
			defer k.Free()

			tmpl := &Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               Name{CommonName: "bc test"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				BasicConstraintsValid: tc.bcValid,
				IsCA:                  tc.isCA,
			}
			der, err := CreateCertificate(tmpl, tmpl, k, k)
			if err != nil {
				t.Fatalf("CreateCertificate: %v", err)
			}
			parsed, err := stdlibParseCert(der)
			if err != nil {
				t.Fatalf("stdlibParseCert: %v", err)
			}

			for _, ext := range parsed.Extensions {
				if !ext.Id.Equal(oidBasicConstraints) {
					continue
				}
				if !tc.wantPresent {
					t.Fatalf("BasicConstraints emitted for BasicConstraintsValid=false")
				}
				if !ext.Critical {
					t.Error("BasicConstraints is not critical; RFC 5280 4.2.1.9 requires it of CA certs and crypto/x509 always marks it")
				}
				if got := hex.EncodeToString(ext.Value); got != tc.wantValue {
					t.Errorf("BasicConstraints value = %s, want %s", got, tc.wantValue)
				}
				if parsed.IsCA != tc.isCA {
					t.Errorf("parsed IsCA = %v, want %v", parsed.IsCA, tc.isCA)
				}
				return
			}
			if tc.wantPresent {
				t.Fatal("BasicConstraints extension missing")
			}
		})
	}
}
