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
	"crypto/x509"
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
