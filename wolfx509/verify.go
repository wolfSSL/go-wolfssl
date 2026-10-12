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
	"bytes"
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
	KeyUsages     []ExtKeyUsage // chain EKUs must permit one; empty skips the check.
}

// Verify runs wolfSSL_X509_verify_cert against Roots, using Intermediates
// as the untrusted chain. wolfSSL enforces CA:TRUE per RFC 5280. On success
// it returns one chain, from a copy of c up to the trust anchor. Every chain
// certificate is a new, fully usable Certificate owned by the caller, who
// releases them with FreeChains (or each Free) rather than waiting on GC.
// Unlike crypto/x509, an empty KeyUsages does not default to server auth.
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

	// Exclusive lock: X509_verify_cert mutates the store (injects
	// intermediates into store->certs, loads/unloads TEMP_CA signers in its
	// CertManager), and wolfSSL does not support concurrent verifies on one
	// store.
	opts.Roots.mu.Lock()
	defer opts.Roots.mu.Unlock()
	if opts.Roots.store == nil {
		return nil, fmt.Errorf("%w: roots pool was freed or failed to initialize", ErrVerifyFailed)
	}

	filtering := len(opts.KeyUsages) > 0 && !hasExtKeyUsage(opts.KeyUsages, ExtKeyUsageAny)
	// A rebuild may drop a Roots certificate that narrowed KeyUsages, so
	// those rebuilds trust only the Roots not yet excluded.
	numInter := len(intermediates)
	if filtering {
		for _, x509 := range opts.Roots.certs {
			if wolfSSL.WolfSSL_X509_up_ref(x509) != wolfSSL.WOLFSSL_SUCCESS {
				return nil, fmt.Errorf("%w: X509_up_ref failed on root pool certificate", ErrVerifyFailed)
			}
			intermediates = append(intermediates, x509)
		}
	}

	ders := make([][]byte, len(intermediates))
	for i, x509 := range intermediates {
		if wolfSSL.WolfSSL_i2d_X509(x509, &ders[i]) <= 0 {
			return nil, fmt.Errorf("%w: i2d_X509 failed on pool certificate", ErrVerifyFailed)
		}
	}

	// wolfSSL builds one path per call. When a path fails KeyUsages, rebuild
	// it without each CA that narrowed the usable set, breadth first.
	queue := [][]bool{make([]bool, len(intermediates))}
	tried := map[string]bool{exclusionKey(queue[0]): true}
	ekuRejected := false
	budget := 2*len(intermediates) + 16
	for attempt := 0; len(queue) > 0; attempt++ {
		if attempt == budget {
			return nil, fmt.Errorf("%w: gave up after %d chain rebuilds looking for one that permits KeyUsages", ErrUnsupported, budget)
		}
		excluded := queue[0]
		queue = queue[1:]
		var stackCerts []*wolfSSL.WOLFSSL_X509
		for i, x509 := range intermediates[:numInter] {
			if !excluded[i] {
				stackCerts = append(stackCerts, x509)
			}
		}
		store := opts.Roots.store
		if filtering {
			anchors, err := anchorStore(intermediates[numInter:], excluded[numInter:])
			if err != nil {
				return nil, err
			}
			store = anchors
		}
		path, err := c.verifyPath(store, stackCerts)
		if filtering {
			wolfSSL.WolfSSL_X509_STORE_free(store)
		}
		if err != nil {
			if ekuRejected {
				continue
			}
			return nil, err
		}
		if !ekuRejected && opts.DNSName != "" && wolfSSL.WolfSSL_X509_check_host(c.x, opts.DNSName) != 1 {
			return nil, fmt.Errorf("%w: %q", ErrHostnameMismatch, opts.DNSName)
		}
		chain, err := parseChain(path)
		if err != nil {
			return nil, err
		}
		allowed, narrowing := chainExtKeyUsage(chain, opts.KeyUsages)
		if allowed {
			return [][]*Certificate{chain}, nil
		}
		FreeChains([][]*Certificate{chain})
		ekuRejected = true
		for _, ca := range narrowing {
			next := append([]bool(nil), excluded...)
			changed := false
			for i := range intermediates {
				if !excluded[i] && bytes.Equal(ders[i], ca.Raw) {
					next[i] = true
					changed = true
				}
			}
			if key := exclusionKey(next); changed && !tried[key] {
				tried[key] = true
				queue = append(queue, next)
			}
		}
	}
	return nil, fmt.Errorf("%w: certificate specifies an incompatible key usage", ErrVerifyFailed)
}

func exclusionKey(excluded []bool) string {
	b := make([]byte, len(excluded))
	for i, e := range excluded {
		if e {
			b[i] = 1
		}
	}
	return string(b)
}

// anchorStore returns a new store trusting each root not marked excluded.
func anchorStore(roots []*wolfSSL.WOLFSSL_X509, excluded []bool) (*wolfSSL.WOLFSSL_X509_STORE, error) {
	store := wolfSSL.WolfSSL_X509_STORE_new()
	if store == nil {
		return nil, fmt.Errorf("%w: X509_STORE_new failed", ErrVerifyFailed)
	}
	for i, x509 := range roots {
		if excluded[i] {
			continue
		}
		if ret := wolfSSL.WolfSSL_X509_STORE_add_cert(store, x509); ret != wolfSSL.WOLFSSL_SUCCESS {
			wolfSSL.WolfSSL_X509_STORE_free(store)
			return nil, fmt.Errorf("%w: X509_STORE_add_cert failed (%d)", ErrVerifyFailed, ret)
		}
	}
	return store, nil
}

// verifyPath runs X509_verify_cert for c with intermediates as the untrusted
// chain and returns the DER of the path wolfSSL built, leaf first.
func (c *Certificate) verifyPath(store *wolfSSL.WOLFSSL_X509_STORE, intermediates []*wolfSSL.WOLFSSL_X509) ([][]byte, error) {
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

	ctx := wolfSSL.WolfSSL_X509_STORE_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("%w: X509_STORE_CTX_new failed", ErrVerifyFailed)
	}
	defer wolfSSL.WolfSSL_X509_STORE_CTX_free(ctx)

	if ret := wolfSSL.WolfSSL_X509_STORE_CTX_init(ctx, store, c.x, stack); ret != wolfSSL.WOLFSSL_SUCCESS {
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

	ders := verifiedChainDER(ctx)
	if len(ders) == 0 {
		return nil, fmt.Errorf("%w: wolfSSL did not report the verified chain", ErrUnsupported)
	}
	if !bytes.Equal(ders[0], c.Raw) {
		return nil, fmt.Errorf("%w: verified chain does not start with the leaf", ErrVerifyFailed)
	}
	return ders, nil
}

// parseChain parses each DER into a new Certificate.
func parseChain(ders [][]byte) ([]*Certificate, error) {
	var chain []*Certificate
	for _, der := range ders {
		cert, err := ParseCertificate(der)
		if err != nil {
			FreeChains([][]*Certificate{chain})
			return nil, fmt.Errorf("%w: parse verified chain: %v", ErrVerifyFailed, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// FreeChains frees every certificate in chains, as returned by Verify.
func FreeChains(chains [][]*Certificate) {
	for _, chain := range chains {
		for _, cert := range chain {
			cert.Free()
		}
	}
}

// chainExtKeyUsage reports whether at least one usage in want is permitted
// by every certificate in chain that carries extendedKeyUsage. When none is,
// it also returns the CAs after the leaf that narrowed the usable set.
// Usages match exactly, as crypto/x509's checkChainForKeyUsage does.
func chainExtKeyUsage(chain []*Certificate, want []ExtKeyUsage) (bool, []*Certificate) {
	if len(want) == 0 || hasExtKeyUsage(want, ExtKeyUsageAny) {
		return true, nil
	}
	var narrowing []*Certificate
	remaining := want
	for i, cert := range chain {
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			continue
		}
		if hasExtKeyUsage(cert.ExtKeyUsage, ExtKeyUsageAny) {
			continue
		}
		var kept []ExtKeyUsage
		for _, u := range remaining {
			if hasExtKeyUsage(cert.ExtKeyUsage, u) {
				kept = append(kept, u)
			}
		}
		if len(kept) < len(remaining) && i > 0 {
			narrowing = append(narrowing, cert)
		}
		remaining = kept
	}
	if len(remaining) > 0 {
		return true, nil
	}
	return false, narrowing
}

func hasExtKeyUsage(usages []ExtKeyUsage, u ExtKeyUsage) bool {
	for _, have := range usages {
		if have == u {
			return true
		}
	}
	return false
}
