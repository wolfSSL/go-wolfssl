/* x509_test.go
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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// loadPEM reads a PEM file and returns the DER bytes of the first CERTIFICATE block.
func loadPEM(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s: no CERTIFICATE PEM block", path)
	}
	return block.Bytes
}

// rawPEM returns the raw PEM bytes, for CertPool.AppendCertsFromPEM.
func rawPEM(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// certsDir resolves the go-wolfssl examples/certs directory relative to this
// test file.
func certsDir(t *testing.T) string {
	t.Helper()
	// tests run with cwd = the package dir; certs live one level up.
	return filepath.Join("..", "examples", "certs")
}

func TestParseCertificateDER(t *testing.T) {
	der := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	if !strings.Contains(cert.Subject.CommonName, "wolfssl.com") {
		t.Errorf("Subject.CommonName = %q, want containing wolfssl.com", cert.Subject.CommonName)
	}
	if cert.Issuer.String() == "" {
		t.Errorf("Issuer.String() returned empty")
	}
	if cert.NotBefore.IsZero() {
		t.Errorf("NotBefore is zero; parse failed")
	}
	if cert.NotAfter.IsZero() {
		t.Errorf("NotAfter is zero; parse failed")
	}
	if !cert.NotBefore.Before(cert.NotAfter) {
		t.Errorf("NotBefore %v not before NotAfter %v", cert.NotBefore, cert.NotAfter)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() == 0 {
		t.Errorf("SerialNumber missing: %v", cert.SerialNumber)
	}
	if len(cert.Raw) != len(der) {
		t.Errorf("Raw len = %d, want %d", len(cert.Raw), len(der))
	}
}

func TestParseCertificateInvalid(t *testing.T) {
	_, err := ParseCertificate(nil)
	if err == nil {
		t.Fatal("expected error on nil DER")
	}
	_, err = ParseCertificate([]byte("not a cert"))
	if err == nil {
		t.Fatal("expected error on garbage DER")
	}
}

func TestVerifyWithRoot(t *testing.T) {
	caPEM := rawPEM(t, filepath.Join(certsDir(t), "ca-cert.pem"))
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))

	pool := NewCertPool()
	defer pool.Free()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM failed")
	}

	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	if _, err := cert.Verify(VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("Verify with correct CA failed: %v", err)
	}
}

func TestVerifyWithoutRoot(t *testing.T) {
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	pool := NewCertPool() // empty
	defer pool.Free()

	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	_, err = cert.Verify(VerifyOptions{Roots: pool})
	if err == nil {
		t.Fatal("Verify with empty pool should have failed")
	}
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("error = %v, want wrapping ErrVerifyFailed", err)
	}
}

// Test chain: ca-cert (self-signed root) → ca-int-cert → ca-int2-cert →
// client-int-cert (leaf).

// newPool returns a CertPool holding the named files from examples/certs.
func newPool(t *testing.T, files ...string) *CertPool {
	t.Helper()
	p := NewCertPool()
	t.Cleanup(p.Free)
	for _, f := range files {
		if !p.AppendCertsFromPEM(rawPEM(t, filepath.Join(certsDir(t), f))) {
			t.Fatalf("AppendCertsFromPEM(%s) failed", f)
		}
	}
	return p
}

// parseCert parses the named file from examples/certs.
func parseCert(t *testing.T, file string) *Certificate {
	t.Helper()
	c, err := ParseCertificate(loadPEM(t, filepath.Join(certsDir(t), file)))
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", file, err)
	}
	t.Cleanup(c.Free)
	return c
}

func TestVerifyChains(t *testing.T) {
	leaf := parseCert(t, "client-int-cert.pem")
	tests := []struct {
		name          string
		roots         *CertPool
		intermediates *CertPool
		wantOK        bool
	}{
		{"full chain", newPool(t, "ca-cert.pem"), newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem"), true},
		{"missing ca-int-cert", newPool(t, "ca-cert.pem"), newPool(t, "ca-int2-cert.pem"), false},
		// Only self-signed certs in Roots are trusted.
		{"non-self-signed root", newPool(t, "ca-int2-cert.pem"), nil, false},
		// Intermediates are never trusted on their own.
		{"no roots", newPool(t), newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem"), false},
	}
	for _, tt := range tests {
		_, err := leaf.Verify(VerifyOptions{Roots: tt.roots, Intermediates: tt.intermediates})
		if (err == nil) != tt.wantOK {
			t.Errorf("%s: err = %v, want ok = %v", tt.name, err, tt.wantOK)
		}
	}
}

// wolfSSL changes the store during verification, so Verify must serialize
// calls on a shared Roots pool. Run passing and failing verifications
// concurrently: if one leaked state into another, results would flip.
func TestVerifyConcurrent(t *testing.T) {
	leaf := parseCert(t, "client-int-cert.pem")
	roots := newPool(t, "ca-cert.pem")
	all := newPool(t, "ca-cert.pem", "ca-int-cert.pem", "ca-int2-cert.pem")
	good := VerifyOptions{Roots: roots, Intermediates: newPool(t, "ca-int-cert.pem", "ca-int2-cert.pem")}
	bad := VerifyOptions{Roots: roots, Intermediates: newPool(t, "ca-int2-cert.pem")}
	samePool := VerifyOptions{Roots: all, Intermediates: all}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, err := leaf.Verify(good); err != nil {
				t.Errorf("good chain failed: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := leaf.Verify(bad); err == nil {
				t.Error("incomplete chain verified")
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := leaf.Verify(samePool); err != nil {
				t.Errorf("same pool as Roots and Intermediates failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestVerifyNilRoots(t *testing.T) {
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	_, err = cert.Verify(VerifyOptions{}) // nil Roots
	if err == nil {
		t.Fatal("Verify with nil Roots should have failed")
	}
}

func TestVerifyHostname(t *testing.T) {
	// server-cert.pem has SAN: DNS:example.com, IP:127.0.0.1; CN: www.wolfssl.com
	serverDER := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	defer cert.Free()

	// Matches SAN
	if err := cert.VerifyHostname("example.com"); err != nil {
		t.Errorf("VerifyHostname(example.com): %v", err)
	}
	// Does not match
	if err := cert.VerifyHostname("not-the-host.example.org"); err == nil {
		t.Error("VerifyHostname should have failed for unrelated host")
	}
}

func TestCertificateSurvivesFree(t *testing.T) {
	der := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Capture fields before Free.
	cn := cert.Subject.CommonName
	notAfter := cert.NotAfter
	rawLen := len(cert.Raw)

	cert.Free()

	// Go-memory fields must still be valid.
	if cert.Subject.CommonName != cn {
		t.Error("Subject.CommonName mutated after Free")
	}
	if !cert.NotAfter.Equal(notAfter) {
		t.Error("NotAfter mutated after Free")
	}
	if len(cert.Raw) != rawLen {
		t.Error("Raw mutated after Free")
	}

	// Verify and VerifyHostname must refuse to dereference the freed pointer.
	if _, err := cert.Verify(VerifyOptions{Roots: NewCertPool()}); err == nil {
		t.Error("Verify after Free should have failed")
	}
	if err := cert.VerifyHostname("example.com"); err == nil {
		t.Error("VerifyHostname after Free should have failed")
	}

	// Double Free is safe.
	cert.Free()
}

func TestConcurrentParse(t *testing.T) {
	der := loadPEM(t, filepath.Join(certsDir(t), "server-cert.pem"))

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			c, err := ParseCertificate(der)
			if err != nil {
				errs <- err
				return
			}
			_ = c.Subject.CommonName
			c.Free()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent parse: %v", err)
	}
}
