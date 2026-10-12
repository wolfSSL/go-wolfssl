/* stdlib_interop_test.go
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
	"math/big"
	"time"
)

func stdlibParseCert(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

func stdlibParseCSR(der []byte) (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(der)
}

func stdlibCheckCSRSignature(c *x509.CertificateRequest) error {
	return c.CheckSignature()
}

func stdlibNewCertPool() *x509.CertPool {
	return x509.NewCertPool()
}

func stdlibAddCert(pool *x509.CertPool, c *x509.Certificate) {
	pool.AddCert(c)
}

// stdlibVerifyLeaf verifies leaf against the supplied root pool using
// crypto/x509's chain builder, optionally with a DNSName check. Returns
// the verification error verbatim so the test can distinguish
// unknown-authority from other failures.
func stdlibVerifyLeaf(leaf *x509.Certificate, roots *x509.CertPool, dnsName string) error {
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: dnsName})
	return err
}

// stdlibCertWithEKUs self-signs a crypto/x509 certificate carrying every
// ExtKeyUsage value wolfx509 defines plus the given unknown EKU OIDs.
func stdlibCertWithEKUs(unknown []asn1.ObjectIdentifier) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "eku.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageIPSECEndSystem,
			x509.ExtKeyUsageIPSECTunnel, x509.ExtKeyUsageIPSECUser,
			x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
			x509.ExtKeyUsageNetscapeServerGatedCrypto,
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftKernelCodeSigning,
		},
		UnknownExtKeyUsage: unknown,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

// stdlibCertWithExtension self-signs a crypto/x509 certificate carrying the
// given raw extension, which replaces any extension crypto/x509 would emit.
func stdlibCertWithExtension(oid asn1.ObjectIdentifier, value []byte) ([]byte, error) {
	return stdlibCertWithExtensions(pkix.Extension{Id: oid, Value: value})
}

// stdlibCertWithExtensions is stdlibCertWithExtension for several raw
// extensions, which may repeat an OID.
func stdlibCertWithExtensions(exts ...pkix.Extension) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "ext.example"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}
