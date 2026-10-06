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
	"encoding/pem"
	"errors"
	"fmt"
	"runtime"
	"sync"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// CertPool is a set of certificates for chain verification.
type CertPool struct {
	mu    sync.RWMutex
	store *wolfSSL.WOLFSSL_X509_STORE
	certs []*wolfSSL.WOLFSSL_X509 // pool's own references; Free releases them.
}

// NewCertPool returns an empty pool.
func NewCertPool() *CertPool {
	pool := &CertPool{store: wolfSSL.WolfSSL_X509_STORE_new()}
	runtime.SetFinalizer(pool, (*CertPool).finalize)
	return pool
}

// Free releases the store and the pool's certificate references. Callers'
// *Certificate values are not affected.
func (pool *CertPool) Free() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.store != nil {
		wolfSSL.WolfSSL_X509_STORE_free(pool.store)
		pool.store = nil
	}
	for _, x509 := range pool.certs {
		wolfSSL.WolfSSL_X509_free(x509)
	}
	pool.certs = nil
	runtime.SetFinalizer(pool, nil)
}

func (pool *CertPool) finalize() { pool.Free() }

// AppendCertsFromPEM parses PEM-encoded certificates and adds each via
// AddCert. Returns true if any cert was added.
func (pool *CertPool) AppendCertsFromPEM(pemCerts []byte) bool {
	var ok bool
	rest := pemCerts
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if pool.AddCert(cert) == nil {
			ok = true
		}
		cert.Free() // the pool holds its own reference
	}
	return ok
}

// AddCert adds cert to the pool. The caller keeps
// ownership of cert: the pool takes its own reference to the underlying X509,
// so cert may be freed, or added to other pools, independently.
func (pool *CertPool) AddCert(cert *Certificate) error {
	if cert == nil {
		return errors.New("wolfx509: AddCert: nil certificate")
	}
	cert.mu.RLock()
	x509 := cert.x
	ret := wolfSSL.WOLFSSL_SUCCESS
	if x509 != nil {
		ret = wolfSSL.WolfSSL_X509_up_ref(x509)
	}
	cert.mu.RUnlock()
	if x509 == nil {
		return errors.New("wolfx509: AddCert: certificate is not parsed (use ParseCertificate) or was freed")
	}
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		return fmt.Errorf("wolfx509: AddCert: X509_up_ref failed (%d)", ret)
	}
	// From here on x509 is our reference: release it on any failure.
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.store == nil {
		wolfSSL.WolfSSL_X509_free(x509)
		return errors.New("wolfx509: AddCert: pool was freed or failed to initialize")
	}
	if ret := wolfSSL.WolfSSL_X509_STORE_add_cert(pool.store, x509); ret != wolfSSL.WOLFSSL_SUCCESS {
		wolfSSL.WolfSSL_X509_free(x509)
		return fmt.Errorf("wolfx509: AddCert: X509_STORE_add_cert failed (%d)", ret)
	}
	pool.certs = append(pool.certs, x509)
	return nil
}
