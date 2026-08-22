/* certgen.go
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
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/wolfssl/go-wolfssl/handles"
)

// ErrUnsupportedCreateMode indicates the current wolfx509 build doesn't
// yet handle the requested CreateCertificate shape (CA-signed, non-ECC
// key, etc.).
var ErrUnsupportedCreateMode = errors.New("wolfx509: unsupported CreateCertificate mode")

// KeyHandle is a wolfCrypt key + RNG suitable for cert/CSR signing or for
// declaring a parsed cert's public-key material. *handles.EccKey is the
// only implementation today.
type KeyHandle interface {
	Algorithm() handles.Algorithm
	CKeyPtr() unsafe.Pointer
	CRngPtr() unsafe.Pointer
}

// CreateCertificate creates a new X.509 v3 certificate. Mirrors
// crypto/x509.CreateCertificate without the io.Reader (wolfCrypt brings
// its own RNG) and with KeyHandle in place of stdlib key types.
//
// Self-signed when template == parent && pubKey == signer; otherwise
// CA-signed (parent.Raw must come from ParseCertificate).
func CreateCertificate(template, parent *Certificate, pubKey, signer KeyHandle) ([]byte, error) {
	if template == nil {
		return nil, errors.New("wolfx509: nil template")
	}
	if parent == nil {
		return nil, errors.New("wolfx509: nil parent (self-signed certs must pass the same template twice)")
	}
	if pubKey == nil || signer == nil {
		return nil, errors.New("wolfx509: nil key")
	}

	notBefore, notAfter, err := resolveValidity(template.NotBefore,
		template.NotAfter, template.ValidDays)
	if err != nil {
		return nil, err
	}

	var serial []byte
	if template.SerialNumber != nil {
		serial = template.SerialNumber.Bytes()
	}

	opts := certBuildOpts{
		SubjectCN:   template.Subject.CommonName,
		Serial:      serial,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		IsCA:        template.IsCA,
		KeyUsage:    translateKeyUsage(template.KeyUsage),
		ExtKeyUsage: translateExtKeyUsage(template.ExtKeyUsage),
		DNSNames:    template.DNSNames,
		IPAddresses: template.IPAddresses,
		AcmeKeyAuth: template.AcmeKeyAuth,
		BasicConstraintsValid: template.BasicConstraintsValid,
	}

	if template == parent && pubKey == signer {
		return makeAndSignSelfSignedCert(opts, signer)
	}
	// CA-signed: need parent.Raw to extract the issuer DN.
	if len(parent.Raw) == 0 {
		return nil, errors.New("wolfx509: parent.Raw is empty; CA cert must be parsed via ParseCertificate first")
	}
	return makeAndSignCASignedCert(opts, parent.Raw, pubKey, signer)
}

// CertificateRequest is the template for CreateCertificateRequest. Mirrors
// the subset of crypto/x509.CertificateRequest that Phase 5b supports.
type CertificateRequest struct {
	Subject            Name
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	SignatureAlgorithm SignatureAlgorithm

	// PublicKey is reserved for symmetry with Certificate.PublicKey;
	// the builder ignores it and uses the key argument.
	PublicKey KeyHandle
}

// SignatureAlgorithm identifies the signature algorithm used to sign a
// CSR or certificate. Only the subset actually produced by wolfCrypt in
// this build is defined.
type SignatureAlgorithm int

const (
	// UnknownSignatureAlgorithm leaves the choice to the builder (it
	// defaults to ECDSA-with-SHA256 in this build).
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	// ECDSAWithSHA256 matches crypto/x509.ECDSAWithSHA256.
	ECDSAWithSHA256
)

// CreateCertificateRequest returns a DER-encoded self-signed PKCS#10 CSR.
// Mirrors crypto/x509.CreateCertificateRequest without the io.Reader and
// with KeyHandle in place of the stdlib priv parameter.
func CreateCertificateRequest(template *CertificateRequest, key KeyHandle) ([]byte, error) {
	if template == nil {
		return nil, errors.New("wolfx509: nil template")
	}
	if key == nil {
		return nil, errors.New("wolfx509: nil key")
	}
	if template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
		template.SignatureAlgorithm != ECDSAWithSHA256 {
		return nil, fmt.Errorf("%w: only ECDSAWithSHA256 is supported", ErrUnsupportedCreateMode)
	}
	return makeAndSignCSR(certBuildOpts{
		SubjectCN:   template.Subject.CommonName,
		DNSNames:    template.DNSNames,
		IPAddresses: template.IPAddresses,
	}, key)
}

// clockSkewBackdate matches wolfCrypt's SetValidity, which subtracts one
// day from notBefore to help with compliance
const clockSkewBackdate = 24 * time.Hour

// ASN.1 GeneralizedTime encodes the year as exactly four digits, so
// years outside this range cannot be represented.
const (
	minASN1Year = 1
	maxASN1Year = 9999
)

// resolveValidity determines the appropriate notBefore and notAfter time values
//
// notAfter is required unless validDays is set; notBefore on its own is an
// error.
//   - notBefore + notAfter: used directly, validDays must be unset
//   - notAfter: notBefore will be set to (now - 1 day)
//   - validDays: notBefore will be set to (now - 1 day) and notAfter will be
//     validDays past now
func resolveValidity(notBefore, notAfter time.Time, validDays int) (time.Time, time.Time, error) {
	notBefore, notAfter = notBefore.Truncate(time.Second), notAfter.Truncate(time.Second)

	if validDays < 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("wolfx509: ValidDays (%d) must not be negative", validDays)
	}
	if !notAfter.IsZero() && validDays > 0 {
		return time.Time{}, time.Time{}, errors.New("wolfx509: set either NotAfter or ValidDays, not both")
	}
	if notAfter.IsZero() && validDays == 0 {
		return time.Time{}, time.Time{}, errors.New("wolfx509: set NotAfter or ValidDays")
	}
	if notAfter.IsZero() && !notBefore.IsZero() {
		return time.Time{}, time.Time{}, errors.New("wolfx509: NotBefore requires NotAfter; ValidDays is measured from issuance, not from NotBefore")
	}

	now := time.Now()
	nb, na := notBefore, notAfter
	if nb.IsZero() {
		nb = now.Add(-clockSkewBackdate)
	}
	if na.IsZero() {
		na = now.Add(time.Duration(validDays) * 24 * time.Hour)
	}

	base := notBefore
	if base.IsZero() {
		base = now
	}
	if !na.After(base) {
		return time.Time{}, time.Time{}, fmt.Errorf("wolfx509: NotAfter (%s) is not after base time (%s)", na, base)
	}
	if y := nb.UTC().Year(); y < minASN1Year || y > maxASN1Year {
		return time.Time{}, time.Time{}, fmt.Errorf("wolfx509: NotBefore year (%d) is outside the encodable range %d-%d", y, minASN1Year, maxASN1Year)
	}
	if y := na.UTC().Year(); y < minASN1Year || y > maxASN1Year {
		return time.Time{}, time.Time{}, fmt.Errorf("wolfx509: NotAfter year (%d) is outside the encodable range %d-%d", y, minASN1Year, maxASN1Year)
	}
	return nb, na, nil
}

// encodeValidityTime encodes ASN.1 for the UTC or GeneralizedTime formats
func encodeValidityTime(t time.Time) []byte {
	var tag byte
	var s string

	t = t.UTC()
	if y := t.Year(); y >= 1950 && y <= 2049 {
		tag = asnUTCTimeTag
		s = t.Format("060102150405Z")
	} else {
		tag = asnGeneralizedTimeTag
		s = t.Format("20060102150405Z")
	}

	out := make([]byte, 2+len(s))
	out[0] = tag
	out[1] = byte(len(s))
	copy(out[2:], s)

	return out
}

// translateKeyUsage maps wolfx509's crypto/x509-shaped KeyUsage bitmask
// (bit 0 = DigitalSignature) onto wolfCrypt's KEYUSE_* bitmask (bit 7 =
// DigitalSignature). The on-the-wire X.509 BIT STRING ordering is the
// same in both cases; only the Go-level constants differ.
func translateKeyUsage(k KeyUsage) int {
	var out int
	if k&KeyUsageDigitalSignature != 0 {
		out |= wcKeyUsageDigitalSignature
	}
	if k&KeyUsageContentCommitment != 0 {
		out |= wcKeyUsageContentCommit
	}
	if k&KeyUsageKeyEncipherment != 0 {
		out |= wcKeyUsageKeyEncipherment
	}
	if k&KeyUsageDataEncipherment != 0 {
		out |= wcKeyUsageDataEncipherment
	}
	if k&KeyUsageKeyAgreement != 0 {
		out |= wcKeyUsageKeyAgreement
	}
	if k&KeyUsageCertSign != 0 {
		out |= wcKeyUsageCertSign
	}
	if k&KeyUsageCRLSign != 0 {
		out |= wcKeyUsageCRLSign
	}
	if k&KeyUsageEncipherOnly != 0 {
		out |= wcKeyUsageEncipherOnly
	}
	return out
}

// translateExtKeyUsage folds a slice of crypto/x509-shaped ExtKeyUsage
// enums into wolfCrypt's EXTKEYUSE_* bitmask.
func translateExtKeyUsage(uses []ExtKeyUsage) int {
	var out int
	for _, u := range uses {
		switch u {
		case ExtKeyUsageAny:
			out |= wcExtKeyUsageAny
		case ExtKeyUsageServerAuth:
			out |= wcExtKeyUsageServerAuth
		case ExtKeyUsageClientAuth:
			out |= wcExtKeyUsageClientAuth
		case ExtKeyUsageCodeSigning:
			out |= wcExtKeyUsageCodeSigning
		case ExtKeyUsageEmailProtection:
			out |= wcExtKeyUsageEmailProt
		case ExtKeyUsageTimeStamping:
			out |= wcExtKeyUsageTimestamp
		case ExtKeyUsageOCSPSigning:
			out |= wcExtKeyUsageOCSPSign
		}
	}
	return out
}
