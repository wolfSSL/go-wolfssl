/* verify.go
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
	"fmt"
	"time"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// VerifyOptions carries the parameters for certificate chain verification.
// Mirrors crypto/x509.VerifyOptions (minimal subset).
type VerifyOptions struct {
	// Roots is the set of trusted CA certificates. Required: Verify
	// returns an error if Roots is nil. Self-signed leaves must be in
	// the pool to validate.
	Roots *CertPool

	// Intermediates is unused — wolfSSL's CertManager-based path can't
	// consume a separate intermediates pool. Verify rejects opts where
	// Intermediates is non-nil rather than silently dropping the data;
	// callers should AppendCertsFromPEM intermediates into Roots.
	Intermediates *CertPool

	// DNSName, if non-empty, is also checked against the leaf's SANs/CN
	// after chain verification succeeds.
	DNSName string

	// CurrentTime is unused — wolfSSL always uses the system clock.
	// Verify rejects opts where CurrentTime is non-zero.
	CurrentTime time.Time
}

// Verify validates c against opts.Roots, then (if DNSName is set) runs
// VerifyHostname. Returns a chain slice for crypto/x509 API symmetry;
// current callers only check err.
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.x == nil {
		return nil, ErrInvalidCert
	}
	if opts.Roots == nil {
		return nil, fmt.Errorf("%w: no roots provided", ErrVerifyFailed)
	}
	// Fail loudly: wolfSSL's CertManager-based path doesn't honor Intermediates
	// or CurrentTime (see field docs). Callers must AppendCertsFromPEM
	// intermediates into Roots and accept the system clock for time checks.
	if opts.Intermediates != nil {
		return nil, fmt.Errorf("%w: Intermediates not supported; load into Roots instead", ErrVerifyFailed)
	}
	if !opts.CurrentTime.IsZero() {
		return nil, fmt.Errorf("%w: CurrentTime not supported; wolfSSL uses the system clock", ErrVerifyFailed)
	}

	opts.Roots.mu.RLock()
	defer opts.Roots.mu.RUnlock()
	if opts.Roots.cm == nil {
		return nil, fmt.Errorf("%w: roots pool is closed", ErrVerifyFailed)
	}

	ret := wolfSSL.WolfSSL_CertManagerVerifyBuffer(opts.Roots.cm, c.Raw)
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		baseErr := fmt.Errorf("%w: wolfSSL_CertManagerVerifyBuffer ret=%d", ErrVerifyFailed, ret)
		// wolfSSL's CertManager returns ASN_NO_SIGNER_E (-188) when the
		// chain can't be rooted in our CA pool. Surface that as an
		// UnknownAuthorityError for stdlib-style errors.As dispatch.
		const ASN_NO_SIGNER_E = -188
		if ret == ASN_NO_SIGNER_E {
			return nil, UnknownAuthorityError{Cert: c, err: baseErr}
		}
		return nil, baseErr
	}

	if opts.DNSName != "" {
		if wolfSSL.WolfSSL_X509_check_host(c.x, opts.DNSName) != 1 {
			return nil, fmt.Errorf("%w: %q", ErrHostnameMismatch, opts.DNSName)
		}
	}

	// Return a placeholder single-element chain — callers only check err.
	return [][]*Certificate{{c}}, nil
}
