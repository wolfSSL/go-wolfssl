/* x509.go
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
)

var (
	ErrInvalidCert      = errors.New("wolfx509: invalid certificate")
	ErrVerifyFailed     = errors.New("wolfx509: certificate verify failed")
	ErrHostnameMismatch = errors.New("wolfx509: hostname does not match certificate")
	ErrUnsupported      = errors.New("wolfx509: operation not supported in this build")
)

// UnknownAuthorityError mirrors crypto/x509.UnknownAuthorityError so
// wolfssl-tagged callers can dispatch on it via errors.As the same way
// they would against the stdlib type. The embedded wrapped error chains
// to ErrVerifyFailed.
type UnknownAuthorityError struct {
	Cert *Certificate
	err  error
}

func (e UnknownAuthorityError) Error() string {
	return "wolfx509: certificate signed by unknown authority"
}

// Unwrap exposes the underlying wolfSSL-reported error (or ErrVerifyFailed
// if none was attached), so errors.Is(err, ErrVerifyFailed) still works
// after an UnknownAuthorityError is returned.
func (e UnknownAuthorityError) Unwrap() error {
	if e.err != nil {
		return e.err
	}
	return ErrVerifyFailed
}
