/* cert_pool.go
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
	"runtime"
	"sync"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// CertPool is a set of trusted CA certificates used during chain
// verification. It wraps a wolfSSL WOLFSSL_CERT_MANAGER; certificates
// are added via AppendCertsFromPEM or AddCert.
type CertPool struct {
	mu sync.RWMutex
	cm *wolfSSL.WOLFSSL_CERT_MANAGER
}

// NewCertPool returns an empty pool backed by a fresh CertManager.
func NewCertPool() *CertPool {
	p := &CertPool{cm: wolfSSL.WolfSSL_CertManagerNew()}
	runtime.SetFinalizer(p, (*CertPool).finalize)
	return p
}

// Free releases the underlying CertManager. Safe to call multiple times.
func (p *CertPool) Free() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cm != nil {
		wolfSSL.WolfSSL_CertManagerFree(p.cm)
		p.cm = nil
	}
	runtime.SetFinalizer(p, nil)
}

func (p *CertPool) finalize() { p.Free() }

// AppendCertsFromPEM loads one or more PEM-encoded CA certificates into the
// pool. Returns true on success. Mirrors crypto/x509.CertPool.AppendCertsFromPEM.
func (p *CertPool) AppendCertsFromPEM(pem []byte) bool {
	if len(pem) == 0 {
		return false
	}
	// Write lock: wolfSSL_CertManagerLoadCABuffer mutates the cert manager,
	// and concurrent loads on the same manager are not safe.
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cm == nil {
		return false
	}
	return wolfSSL.WolfSSL_CertManagerLoadCABuffer(p.cm, pem, wolfSSL.SSL_FILETYPE_PEM) == wolfSSL.WOLFSSL_SUCCESS
}

// AddCert appends a single certificate to the pool via wolfSSL's
// CertManagerLoadCABuffer in DER mode. Unlike crypto/x509.CertPool.AddCert
// (which is infallible because the cert is already parsed in Go memory),
// wolfSSL re-parses the DER inside its cert manager and can reject it.
// Callers must check the returned error; a silent failure here leads to
// chains not verifying later with no clue why.
func (p *CertPool) AddCert(c *Certificate) error {
	if c == nil || len(c.Raw) == 0 {
		return errors.New("wolfx509: AddCert: nil certificate or empty DER")
	}
	// Write lock: see AppendCertsFromPEM.
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cm == nil {
		return errors.New("wolfx509: AddCert: pool already freed")
	}
	if ret := wolfSSL.WolfSSL_CertManagerLoadCABuffer(p.cm, c.Raw, wolfSSL.SSL_FILETYPE_ASN1); ret != wolfSSL.WOLFSSL_SUCCESS {
		return fmt.Errorf("wolfx509: AddCert: wolfSSL rejected DER (%d)", ret)
	}
	return nil
}
