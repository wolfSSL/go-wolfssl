/* certgen.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
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

	days, err := validityDays(template.NotBefore, template.NotAfter)
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
		ValidDays:   days,
		IsCA:        template.IsCA,
		KeyUsage:    translateKeyUsage(template.KeyUsage),
		ExtKeyUsage: translateExtKeyUsage(template.ExtKeyUsage),
		DNSNames:    template.DNSNames,
		IPAddresses: template.IPAddresses,
		AcmeKeyAuth: template.AcmeKeyAuth,
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

// validityDays converts a NotBefore/NotAfter pair into a whole-days count
// suitable for wolfCrypt's Cert.daysValid. wolfCrypt computes NotBefore
// as "now"; if template.NotBefore is set in the past (e.g. derper's -30d
// for clock-skew tolerance), we extend daysValid to cover NotAfter from
// "now" instead of from NotBefore.
func validityDays(notBefore, notAfter time.Time) (int, error) {
	if notAfter.IsZero() {
		return 0, errors.New("wolfx509: template.NotAfter is required")
	}
	ref := time.Now()
	if notBefore.Before(ref) && !notBefore.IsZero() {
		// NotBefore in the past — use it as the anchor so the certificate
		// spans the full requested window.
		ref = notBefore
	}
	d := notAfter.Sub(ref)
	if d <= 0 {
		return 0, fmt.Errorf("wolfx509: NotAfter (%s) is not after the effective NotBefore (%s)", notAfter, ref)
	}
	days := int(d / (24 * time.Hour))
	if days == 0 {
		days = 1
	}
	return days, nil
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
