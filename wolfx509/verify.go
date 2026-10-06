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
	Roots         *CertPool     // trust anchors; required.
	Intermediates *CertPool     // wire-presented intermediates; optional.
	DNSName       string        // checked against SANs after chain verify.
	CurrentTime   time.Time     // rejected if non-zero (wolfSSL uses system clock).
}

// Verify runs wolfSSL_X509_verify_cert against Roots, using Intermediates
// as the untrusted chain. wolfSSL enforces CA:TRUE per RFC 5280.
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.x == nil {
		return nil, ErrInvalidCert
	}
	if opts.Roots == nil {
		return nil, fmt.Errorf("%w: no roots provided", ErrVerifyFailed)
	}
	if !opts.CurrentTime.IsZero() {
		return nil, fmt.Errorf("%w: CurrentTime not supported; wolfSSL uses the system clock", ErrVerifyFailed)
	}

	// Take our own reference on each intermediate so we don't need to hold
	// the Intermediates lock during verification; a concurrent Free of that
	// pool can't release them while wolfSSL is using them.
	var intermediates []*wolfSSL.WOLFSSL_X509
	defer func() {
		for _, x509 := range intermediates {
			wolfSSL.WolfSSL_X509_free(x509)
		}
	}()
	if opts.Intermediates != nil {
		opts.Intermediates.mu.RLock()
		upRefOK := true
		for _, x509 := range opts.Intermediates.certs {
			if wolfSSL.WolfSSL_X509_up_ref(x509) != wolfSSL.WOLFSSL_SUCCESS {
				upRefOK = false
				break
			}
			intermediates = append(intermediates, x509)
		}
		opts.Intermediates.mu.RUnlock()
		if !upRefOK {
			return nil, fmt.Errorf("%w: X509_up_ref failed on intermediate", ErrVerifyFailed)
		}
	}

	stack := wolfSSL.WolfSSL_sk_X509_new_null()
	if stack == nil {
		return nil, fmt.Errorf("%w: sk_X509_new_null failed", ErrVerifyFailed)
	}
	defer wolfSSL.WolfSSL_sk_X509_free(stack)
	for _, x509 := range intermediates {
		if ret := wolfSSL.WolfSSL_sk_X509_push(stack, x509); ret <= 0 {
			return nil, fmt.Errorf("%w: sk_X509_push failed (ret=%d)", ErrVerifyFailed, ret)
		}
	}

	// Exclusive lock: X509_verify_cert mutates the store (injects
	// intermediates into store->certs, loads/unloads TEMP_CA signers in its
	// CertManager), and wolfSSL does not support concurrent verifies on one
	// store.
	opts.Roots.mu.Lock()
	defer opts.Roots.mu.Unlock()
	if opts.Roots.store == nil {
		return nil, fmt.Errorf("%w: roots pool was freed or failed to initialize", ErrVerifyFailed)
	}

	ctx := wolfSSL.WolfSSL_X509_STORE_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("%w: X509_STORE_CTX_new failed", ErrVerifyFailed)
	}
	defer wolfSSL.WolfSSL_X509_STORE_CTX_free(ctx)

	if ret := wolfSSL.WolfSSL_X509_STORE_CTX_init(ctx, opts.Roots.store, c.x, stack); ret != wolfSSL.WOLFSSL_SUCCESS {
		return nil, fmt.Errorf("%w: X509_STORE_CTX_init failed (ret=%d)", ErrVerifyFailed, ret)
	}

	if ret := wolfSSL.WolfSSL_X509_verify_cert(ctx); ret != wolfSSL.WOLFSSL_SUCCESS {
		code := wolfSSL.WolfSSL_X509_STORE_CTX_get_error(ctx)
		if code == 0 {
			return nil, fmt.Errorf("%w: X509_verify_cert failed (ret=%d)", ErrVerifyFailed, ret)
		}
		verifyErr := fmt.Errorf("%w: X509_V_ERR %d", ErrVerifyFailed, code)
		// Callers may check errors.As(err, &UnknownAuthorityError{}) as with crypto/x509, so return it for "no trusted issuer" codes.
		switch code {
		case wolfSSL.WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
			wolfSSL.WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return nil, UnknownAuthorityError{Cert: c, err: verifyErr}
		}
		return nil, verifyErr
	}

	if opts.DNSName != "" {
		if wolfSSL.WolfSSL_X509_check_host(c.x, opts.DNSName) != 1 {
			return nil, fmt.Errorf("%w: %q", ErrHostnameMismatch, opts.DNSName)
		}
	}

	return [][]*Certificate{{c}}, nil
}
