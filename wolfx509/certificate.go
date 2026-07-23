/* certificate.go
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
	"fmt"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	wolfSSL "github.com/wolfssl/go-wolfssl"
	"github.com/wolfssl/go-wolfssl/handles"
)

// Certificate is a parsed X.509 certificate. Fields are populated in
// Go memory at parse time so reads are safe without holding any lock.
// The underlying wolfSSL *WOLFSSL_X509 is retained for Verify and is
// freed when Free is called or the Certificate is garbage-collected.
type Certificate struct {
	Raw                   []byte
	RawSubject            []byte
	RawIssuer             []byte
	Subject               Name
	Issuer                Name
	NotBefore             time.Time
	NotAfter              time.Time
	SerialNumber          *big.Int
	AuthorityKeyId        []byte
	BasicConstraintsValid bool
	IsCA                  bool
	KeyUsage              KeyUsage
	ExtKeyUsage           []ExtKeyUsage
	EmailAddresses        []string
	DNSNames              []string
	IPAddresses           []net.IP

	// ValidDays, if set, will set the number of days a certificate is valid
	// for. This field is mutually exclusive with NotAfter.
	ValidDays int

	// AcmeKeyAuth, if non-empty, sets the RFC 8737 id-pe-acmeIdentifier
	// (1.3.6.1.5.5.7.1.31) extension on the cert at build time. Used by
	// TLS-ALPN-01 ACME challenge cert minting. Pass the raw keyAuth
	// string (token "." JWK_thumbprint per RFC 8555 §8.1); wolfCrypt
	// computes SHA-256 over it internally and stores the digest as
	// the extension value.
	AcmeKeyAuth []byte

	// PublicKey is populated by ParseCertificate from the SPKI when the
	// algorithm is supported (only AlgECDSAP256 today). Owned by the
	// Certificate and released in Free(); set by template callers
	// is ignored by the builder.
	PublicKey KeyHandle

	// mu guards the underlying *WOLFSSL_X509 against use-after-free
	// between Verify (which dereferences x) and Free (which releases it).
	mu sync.RWMutex
	x  *wolfSSL.WOLFSSL_X509
	// publicKeyOwned distinguishes parser-allocated PublicKey (we Free
	// it) from caller-set PublicKey on a template (caller owns it).
	publicKeyOwned bool
}

// KeyUsage represents the set of actions that are valid for a given key.
// Values match crypto/x509.KeyUsage so consumers can mix types with a
// numeric cast.
type KeyUsage int

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

// ExtKeyUsage represents an extended key-usage OID. Values match
// crypto/x509.ExtKeyUsage.
type ExtKeyUsage int

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
)

// ParseCertificate parses a DER-encoded X.509 certificate. Returns a
// *Certificate with all readable fields populated.
func ParseCertificate(der []byte) (*Certificate, error) {
	if len(der) == 0 {
		return nil, ErrInvalidCert
	}
	x := wolfSSL.WolfSSL_X509_load_certificate_buffer(der, len(der), wolfSSL.SSL_FILETYPE_ASN1)
	if x == nil {
		return nil, fmt.Errorf("%w: wolfSSL_X509_load_certificate_buffer returned NULL", ErrInvalidCert)
	}

	subject := nameFromWolfSSL(wolfSSL.WolfSSL_X509_get_subject_name(x))
	if subject.CommonName == "" {
		// Fallback to the direct accessor, which some wolfSSL builds expose
		// even when NAME_get_text_by_NID doesn't find the RDN by number.
		subject.CommonName = wolfSSL.WolfSSL_X509_get_subjectCN(x)
	}

	notBefore, err := parseASN1Time(wolfSSL.WolfSSL_X509_get_notBefore_str(x))
	if err != nil {
		wolfSSL.WolfSSL_X509_free(x)
		return nil, fmt.Errorf("notBefore: %w", err)
	}
	notAfter, err := parseASN1Time(wolfSSL.WolfSSL_X509_get_notAfter_str(x))
	if err != nil {
		wolfSSL.WolfSSL_X509_free(x)
		return nil, fmt.Errorf("notAfter: %w", err)
	}

	c := &Certificate{
		x:         x,
		Raw:       append([]byte(nil), der...),
		Subject:   subject,
		Issuer:    nameFromWolfSSL(wolfSSL.WolfSSL_X509_get_issuer_name(x)),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	if s := wolfSSL.WolfSSL_X509_get_serial_bytes(x); len(s) > 0 {
		c.SerialNumber = new(big.Int).SetBytes(s)
	} else {
		c.SerialNumber = new(big.Int)
	}

	// AKI keyIdentifier — used by ACME ARI's {AKI}.{Serial} renewal
	// identifier (draft-ietf-acme-ari). Absent for self-signed leaves
	// and for CAs that omit the extension, in which case this stays nil
	// and callers must fall back (e.g. expiry-based renewal).
	c.AuthorityKeyId = wolfSSL.WolfSSL_X509_get_authority_key_id(x)

	// RawSubject / RawIssuer: re-encode the names via i2d. wolfSSL exposes
	// i2d_X509_NAME but it's not universally available in the OpenSSL-extra
	// subset. For now, leave these nil — Tailscale's certIsSelfSigned
	// equivalent uses a different check via Subject.String() == Issuer.String().

	// SPKI decode failures (e.g. unsupported algorithm) leave PublicKey
	// nil; the rest of the cert is still usable for chain verification.
	if pk, ok := parseSpkiAsKeyHandle(x); ok {
		c.PublicKey = pk
		c.publicKeyOwned = true
	}

	// Attach finalizer so leaked Certificates don't leak the WOLFSSL_X509.
	runtime.SetFinalizer(c, (*Certificate).finalize)
	return c, nil
}

// parseSpkiAsKeyHandle decodes the cert's SPKI as ECC; returns ok=false
// for any other algorithm or on decode error.
func parseSpkiAsKeyHandle(x *wolfSSL.WOLFSSL_X509) (KeyHandle, bool) {
	spki := make([]byte, 256)
	spkiLen := len(spki)
	if ret := wolfSSL.WolfSSL_X509_get_pubkey_buffer(x, spki, &spkiLen); ret != 1 {
		return nil, false
	}
	spki = spki[:spkiLen]

	k, err := handles.NewEmptyEccPubKey()
	if err != nil {
		return nil, false
	}
	idx := 0
	if ret := wolfSSL.Wc_EccPublicKeyDecode(spki, &idx, k.Raw(), len(spki)); ret != 0 {
		k.Free()
		return nil, false
	}
	k.MarkLive()
	return k, true
}

// Free releases the underlying WOLFSSL_X509 and any parser-owned
// PublicKey. Safe to call multiple times and from multiple goroutines.
// After Free, Verify returns ErrInvalidCert, but the copied Go-memory
// fields remain readable.
func (c *Certificate) Free() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.x != nil {
		wolfSSL.WolfSSL_X509_free(c.x)
		c.x = nil
	}
	if c.publicKeyOwned && c.PublicKey != nil {
		if k, ok := c.PublicKey.(*handles.EccKey); ok {
			k.Free()
		}
		c.PublicKey = nil
		c.publicKeyOwned = false
	}
	runtime.SetFinalizer(c, nil)
}

// finalize is the finalizer wrapper (stable method pointer for SetFinalizer).
func (c *Certificate) finalize() { c.Free() }

// Equal reports whether two certificates are the same on the wire.
func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return c == other
	}
	return bytes.Equal(c.Raw, other.Raw)
}

// VerifyHostname checks whether host matches the certificate's SANs or CN.
// Implemented via wolfSSL_X509_check_host, which handles IP SANs too.
func (c *Certificate) VerifyHostname(host string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.x == nil {
		return ErrInvalidCert
	}
	if wolfSSL.WolfSSL_X509_check_host(c.x, host) == 1 {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrHostnameMismatch, host)
}

// ParseCertificates parses a concatenation of one or more DER-encoded X.509
// certificates (the wire format of a TLS certificate chain or an ACME
// finalize response body). Each cert is a top-level ASN.1 SEQUENCE; this
// walks the input slicing successive SEQUENCEs and delegating each to
// ParseCertificate.
func ParseCertificates(der []byte) ([]*Certificate, error) {
	if len(der) == 0 {
		return nil, ErrInvalidCert
	}
	var out []*Certificate
	rest := der
	for len(rest) > 0 {
		n, err := derSequenceLen(rest)
		if err != nil {
			return nil, err
		}
		if n > len(rest) {
			return nil, fmt.Errorf("%w: truncated cert: need %d bytes, have %d", ErrInvalidCert, n, len(rest))
		}
		cert, err := ParseCertificate(rest[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
		rest = rest[n:]
	}
	return out, nil
}

// derSequenceLen returns the total length (header + content) of the
// top-level ASN.1 SEQUENCE that begins at b[0]. Errors if the buffer
// doesn't start with a SEQUENCE tag (0x30) or is too short to contain
// the length field.
func derSequenceLen(b []byte) (int, error) {
	if len(b) < 2 {
		return 0, fmt.Errorf("%w: too short for ASN.1 header", ErrInvalidCert)
	}
	if b[0] != 0x30 {
		return 0, fmt.Errorf("%w: expected SEQUENCE tag (0x30), got 0x%02x", ErrInvalidCert, b[0])
	}
	first := b[1]
	if first&0x80 == 0 {
		return 2 + int(first), nil
	}
	nlen := int(first & 0x7f)
	if nlen == 0 || nlen > 4 {
		return 0, fmt.Errorf("%w: unsupported ASN.1 long-form length (%d bytes)", ErrInvalidCert, nlen)
	}
	if len(b) < 2+nlen {
		return 0, fmt.Errorf("%w: truncated length field", ErrInvalidCert)
	}
	n := 0
	for i := 0; i < nlen; i++ {
		n = (n << 8) | int(b[2+i])
	}
	return 2 + nlen + n, nil
}

// PublicECCRawXY extracts the leaf certificate's ECDSA P-256 public point
// as raw big-endian X/Y coordinates (32 bytes each). Returns an error if
// the certificate's public key is not ECC (PublicKey nil after parse).
// Used to compare a parsed leaf's public key against a candidate
// *handles.EccKey via handles.PublicRawXY.
func (c *Certificate) PublicECCRawXY() (x, y []byte, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.x == nil {
		return nil, nil, ErrInvalidCert
	}
	k, ok := c.PublicKey.(*handles.EccKey)
	if !ok || k == nil || !k.IsLive() {
		return nil, nil, fmt.Errorf("%w: leaf certificate has no ECC public key", ErrInvalidCert)
	}
	x = make([]byte, 32)
	y = make([]byte, 32)
	xLen := len(x)
	yLen := len(y)
	if ret := wolfSSL.Wc_ecc_export_public_raw(k.Raw(), x, &xLen, y, &yLen); ret != 0 {
		return nil, nil, fmt.Errorf("%w: wc_ecc_export_public_raw: %d", ErrInvalidCert, ret)
	}
	return x[:xLen], y[:yLen], nil
}

// asn1TimeLayouts are the formats wolfSSL_ASN1_TIME_print emits for
// UTCTime and GeneralizedTime values.
var asn1TimeLayouts = []string{
	"Jan _2 15:04:05 2006 MST", // default ASN1_TIME_print output
	"Jan 2 15:04:05 2006 MST",  // fallback for single-digit day
	"Jan _2 15:04:05 2006 GMT", // some wolfSSL builds emit GMT
}

// parseASN1Time parses the printable string produced by
// wolfSSL_ASN1_TIME_print into a Go time.Time. Returns an error if the
// input is empty or doesn't match any known layout.
func parseASN1Time(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("%w: empty ASN.1 time string", ErrInvalidCert)
	}
	for _, layout := range asn1TimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: unrecognized ASN.1 time format %q", ErrInvalidCert, s)
}
