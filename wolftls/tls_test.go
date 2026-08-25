/* tls_test.go
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

package wolftls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func certPath(name string) string {
	return filepath.Join("..", "examples", "certs", name)
}

func loadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}

func TestClientServerHandshake(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))
	caPEM := loadFile(t, certPath("ca-cert.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		RootCAPEMs:         [][]byte{caPEM},
	}

	// Create TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	testMsg := []byte("hello from client")
	replyMsg := []byte("hello from server")

	errc := make(chan error, 1)

	// Server goroutine
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- fmt.Errorf("accept: %w", err)
			return
		}

		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()

		if err := tlsConn.Handshake(); err != nil {
			errc <- fmt.Errorf("server handshake: %w", err)
			return
		}

		buf := make([]byte, 256)
		n, err := tlsConn.Read(buf)
		if err != nil {
			errc <- fmt.Errorf("server read: %w", err)
			return
		}

		if !bytes.Equal(buf[:n], testMsg) {
			errc <- fmt.Errorf("server got %q, want %q", buf[:n], testMsg)
			return
		}

		_, err = tlsConn.Write(replyMsg)
		if err != nil {
			errc <- fmt.Errorf("server write: %w", err)
			return
		}

		errc <- nil
	}()

	// Client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}

	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Check connection state
	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatal("handshake not marked complete")
	}
	if state.Version == 0 {
		t.Fatal("TLS version is 0")
	}
	if state.CipherSuite == "" {
		t.Fatal("cipher suite is empty")
	}

	// Send message
	_, err = tlsConn.Write(testMsg)
	if err != nil {
		t.Fatalf("client write: %v", err)
	}

	// Read reply
	buf := make([]byte, 256)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf[:n], replyMsg) {
		t.Fatalf("client got %q, want %q", buf[:n], replyMsg)
	}

	// Wait for server
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestVerifyConnectionCallback(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	callbackCalled := false
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		VerifyConnection: func(cs ConnectionState) error {
			callbackCalled = true
			if !cs.HandshakeComplete {
				return fmt.Errorf("expected handshake complete")
			}
			return nil
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if !callbackCalled {
		t.Fatal("VerifyConnection callback was not called")
	}

	if err := <-errc; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestNewListener(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	ln := NewListener(inner, serverConfig)
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("via listener"))
		errc <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	buf := make([]byte, 256)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "via listener" {
		t.Fatalf("got %q, want %q", buf[:n], "via listener")
	}

	if err := <-errc; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestPeerCertificatesPopulated(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	var gotCerts int
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		VerifyConnection: func(cs ConnectionState) error {
			gotCerts = len(cs.PeerCertificates)
			if gotCerts == 0 {
				return fmt.Errorf("expected peer certificates, got none")
			}
			// Verify it's non-empty DER data
			if len(cs.PeerCertificates[0]) == 0 {
				return fmt.Errorf("leaf cert DER is empty")
			}
			return nil
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if gotCerts == 0 {
		t.Fatal("VerifyConnection never received peer certificates")
	}
	t.Logf("peer certificate count: %d", gotCerts)

	// Also check ConnectionState directly
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("ConnectionState().PeerCertificates is empty")
	}

	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestVerifyPeerCertificateCallback(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	callbackCalled := false
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte) error {
			callbackCalled = true
			if len(rawCerts) == 0 {
				return fmt.Errorf("expected raw certs, got none")
			}
			// Verify the DER bytes are non-empty
			if len(rawCerts[0]) == 0 {
				return fmt.Errorf("first cert DER is empty")
			}
			return nil
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if !callbackCalled {
		t.Fatal("VerifyPeerCertificate callback was not called")
	}

	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestRootCAPEMsVerification(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))
	caPEM := loadFile(t, certPath("ca-cert.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	// Client with CA loaded — wolfSSL should verify the server cert
	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: false,
		RootCAPEMs:         [][]byte{caPEM},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		t.Fatalf("handshake with valid CA should succeed: %v", err)
	}

	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestRootCAPEMsRejectsWrongCA(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	// Client with NO root CAs and verification enabled — should fail
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: false,
		// No RootCAPEMs — wolfSSL won't trust the server cert
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err == nil {
		t.Fatal("handshake without correct CA should have failed")
	}
	t.Logf("expected handshake failure: %v", err)

	// Server side may also error — that's fine
	<-errc
}

func TestVerifyHostnameMismatch(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))
	caPEM := loadFile(t, certPath("ca-cert.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	// Trusted chain (CA loaded), but ServerName is not in the cert's SAN
	// (which only covers example.com / 127.0.0.1).
	clientConfig := &Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: false,
		RootCAPEMs:         [][]byte{caPEM},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err == nil {
		t.Fatal("handshake should fail: cert SAN does not cover ServerName")
	}
	// Assert the failure is the hostname check rejecting the leaf cert
	// during the handshake
	if !strings.Contains(err.Error(), "-322") {
		t.Fatalf("expected DOMAIN_NAME_MISMATCH (-322) hostname-verification failure, got: %v", err)
	}
	t.Logf("expected hostname-mismatch failure: %v", err)

	// Server side may also error from the client's alert — that's fine.
	<-errc
}

// TestVerifyFailsClosedWhenServerNameEmpty checks that a client with peer
// verification enabled (InsecureSkipVerify == false) but no ServerName is
// rejected before the handshake, matching crypto/tls.
//
// The server presents a certificate that chains to the trusted CA but is
// issued for example.com / 127.0.0.1. doHandshake only performs the
// certificate name check when ServerName is non-empty, so with an empty
// ServerName the name is never checked while the trusted chain is still
// accepted. crypto/tls rejects this configuration ("either ServerName or
// InsecureSkipVerify must be specified"); wolftls should do the same.
func TestVerifyFailsClosedWhenServerNameEmpty(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))
	caPEM := loadFile(t, certPath("ca-cert.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	// Verification ON, but no ServerName.
	clientConfig := &Config{
		ServerName:         "",
		InsecureSkipVerify: false,
		RootCAPEMs:         [][]byte{caPEM},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err == nil {
		t.Fatal("client handshake succeeded with verification enabled but " +
			"empty ServerName — the certificate name was never checked. " +
			"Expected the handshake to be rejected, as crypto/tls does.")
	}
	// Assert it is the fail-closed guard rejecting the config, not an unrelated
	// failure, so the test keeps pinning the guard if the handshake path changes.
	if !strings.Contains(err.Error(),
		"either ServerName or InsecureSkipVerify must be specified") {
		t.Fatalf("expected the ServerName-required guard error, got: %v", err)
	}
	t.Logf("failed closed as expected: %v", err)

	// The client rejected the config before sending a ClientHello, so close
	// the connection to unblock the server's handshake read, then drain it.
	tlsConn.Close()
	<-errc
}

// A client with InsecureSkipVerify set may omit ServerName: the fail-closed
// guard must not fire and the handshake must complete. This pins the guard's
// !InsecureSkipVerify condition so it is not later simplified into rejecting
// every empty-ServerName client.
func TestInsecureSkipVerifyAllowsEmptyServerName(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	// Verification OFF and no ServerName: allowed, guard must not fire.
	clientConfig := &Config{
		ServerName:         "",
		InsecureSkipVerify: true,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake should succeed with InsecureSkipVerify and "+
			"empty ServerName, got: %v", err)
	}

	if err := <-errc; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}
}

func TestMinMaxVersion(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	tests := []struct {
		name       string
		minVersion uint16
		maxVersion uint16
		wantVer    uint16
		wantName   string
	}{
		{"TLS 1.2 only", VersionTLS12, VersionTLS12, VersionTLS12, "TLS 1.2"},
		{"TLS 1.3 only", VersionTLS13, VersionTLS13, VersionTLS13, "TLS 1.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConfig := &Config{
				Certificates: []Certificate{{
					CertPEM: certPEM,
					KeyPEM:  keyPEM,
				}},
				MinVersion: tt.minVersion,
				MaxVersion: tt.maxVersion,
			}

			clientConfig := &Config{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
				MinVersion:         tt.minVersion,
				MaxVersion:         tt.maxVersion,
			}

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			errc := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					errc <- err
					return
				}
				tlsConn := Server(conn, serverConfig)
				defer tlsConn.Close()
				errc <- tlsConn.Handshake()
			}()

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			tlsConn := Client(conn, clientConfig)
			defer tlsConn.Close()

			if err := tlsConn.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}

			state := tlsConn.ConnectionState()
			if state.Version != tt.wantVer {
				t.Fatalf("expected %s (0x%x), got 0x%x", tt.wantName, tt.wantVer, state.Version)
			}
			t.Logf("negotiated version: 0x%x (%s)", state.Version, tt.wantName)

			if err := <-errc; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestGetCertificate(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	callbackCalled := false
	serverConfig := &Config{
		// No static Certificates — rely on GetCertificate
		GetCertificate: func(hello *ClientHelloInfo) (*Certificate, error) {
			callbackCalled = true
			t.Logf("GetCertificate called for SNI: %q", hello.ServerName)
			return &Certificate{
				CertPEM: certPEM,
				KeyPEM:  keyPEM,
			}, nil
		},
		// Need a default cert for wolfSSL to start — load one statically too
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	clientConfig := &Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			errc <- err
			return
		}
		_, err = tlsConn.Write([]byte("hello"))
		errc <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	buf := make([]byte, 256)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q, want %q", buf[:n], "hello")
	}

	if !callbackCalled {
		t.Fatal("GetCertificate was not called")
	}

	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestPeerCertsSurviveClose(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		errc <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Grab certs before close
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certs")
	}
	savedDER := make([]byte, len(state.PeerCertificates[0]))
	copy(savedDER, state.PeerCertificates[0])

	// Close frees wolfSSL objects
	tlsConn.Close()
	<-errc

	// Verify the DER bytes are still valid (Go-owned copy, not a dangling C pointer)
	if len(state.PeerCertificates[0]) == 0 {
		t.Fatal("peer cert DER became empty after close")
	}
	if !bytes.Equal(savedDER, state.PeerCertificates[0]) {
		t.Fatal("peer cert DER changed after close — possible use-after-free")
	}
	t.Logf("peer cert (%d bytes DER) survived close", len(savedDER))
}

func TestNetPipe(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	// net.Pipe() — no OS socket, no file descriptor
	clientConn, serverConn := net.Pipe()

	errc := make(chan error, 1)
	go func() {
		tlsConn := Server(serverConn, serverConfig)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			errc <- err
			return
		}
		_, err := tlsConn.Write([]byte("hello from pipe"))
		errc <- err
	}()

	tlsConn := Client(clientConn, clientConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake over net.Pipe: %v", err)
	}

	buf := make([]byte, 256)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello from pipe" {
		t.Fatalf("got %q, want %q", buf[:n], "hello from pipe")
	}

	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestALPN(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
		NextProtos: []string{"h2", "http/1.1"},
	}

	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverProto string
	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			errc <- err
			return
		}
		serverProto = tlsConn.ConnectionState().NegotiatedProtocol
		errc <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := Client(conn, clientConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	clientProto := tlsConn.ConnectionState().NegotiatedProtocol
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}

	if clientProto != "h2" {
		t.Fatalf("client ALPN: got %q, want %q", clientProto, "h2")
	}
	if serverProto != "h2" {
		t.Fatalf("server ALPN: got %q, want %q", serverProto, "h2")
	}
	t.Logf("ALPN negotiated: client=%q server=%q", clientProto, serverProto)
}

func TestDial(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		}},
	}

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer inner.Close()

	errc := make(chan error, 1)
	go func() {
		conn, err := inner.Accept()
		if err != nil {
			errc <- err
			return
		}
		tlsConn := Server(conn, serverConfig)
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			errc <- err
			return
		}
		_, err = tlsConn.Write([]byte("hello via Dial"))
		errc <- err
	}()

	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	tlsConn, err := Dial("tcp", inner.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tlsConn.Close()

	buf := make([]byte, 256)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello via Dial" {
		t.Fatalf("got %q, want %q", buf[:n], "hello via Dial")
	}

	if err := <-errc; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// --- helpers for tests below ---

func setupPair(t *testing.T) (client *Conn, server *Conn, cleanup func()) {
	t.Helper()
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{CertPEM: certPEM, KeyPEM: keyPEM}},
	}
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	// Use TCP instead of net.Pipe to avoid synchronous I/O deadlocks
	// during TLS 1.3 handshake (post-handshake messages like NewSessionTicket).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	errc := make(chan error, 1)
	var srv *Conn
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv = Server(conn, serverConfig)
		errc <- srv.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}
	defer ln.Close()

	cli := Client(conn, clientConfig)
	if err := cli.Handshake(); err != nil {
		cli.Close()
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		cli.Close()
		if srv != nil {
			srv.Close()
		}
		t.Fatalf("server handshake: %v", err)
	}

	return cli, srv, func() {
		cli.Close()
		srv.Close()
	}
}

func TestHandshakeCancelContext(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))

	serverConfig := &Config{
		Certificates: []Certificate{{CertPEM: certPEM, KeyPEM: keyPEM}},
	}
	clientConfig := &Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	t.Run("already canceled", func(t *testing.T) {
		cConn, sConn := net.Pipe()
		defer sConn.Close()

		cli := Client(cConn, clientConfig)
		defer cli.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already canceled

		start := time.Now()
		err := cli.HandshakeContext(ctx)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected handshake to fail with canceled context")
		}
		t.Logf("failed in %v: %v", elapsed, err)
		if elapsed > 2*time.Second {
			t.Fatalf("took %v — cancellation didn't unblock", elapsed)
		}
	})

	t.Run("timeout during handshake", func(t *testing.T) {
		cConn, sConn := net.Pipe()
		defer sConn.Close()

		// Server never handshakes — client will block
		_ = Server(sConn, serverConfig)

		cli := Client(cConn, clientConfig)
		defer cli.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		start := time.Now()
		err := cli.HandshakeContext(ctx)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected handshake to fail with timeout")
		}
		t.Logf("failed in %v: %v", elapsed, err)
		if elapsed > 2*time.Second {
			t.Fatalf("took %v — timeout didn't unblock", elapsed)
		}
	})
}

func TestReadDeadline(t *testing.T) {
	cli, srv, cleanup := setupPair(t)
	defer cleanup()

	// Server never writes — client read should hit the deadline.
	_ = srv

	cli.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	start := time.Now()
	buf := make([]byte, 64)
	_, err := cli.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected read to fail with deadline")
	}
	t.Logf("read deadline hit in %v: %v", elapsed, err)
	if elapsed > 2*time.Second {
		t.Fatalf("took %v — deadline didn't fire", elapsed)
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("returned too fast (%v)", elapsed)
	}
}

func TestWriteDeadline(t *testing.T) {
	cli, srv, cleanup := setupPair(t)
	defer cleanup()

	// Server never reads — writes will eventually block.
	_ = srv

	cli.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))

	data := make([]byte, 16384)
	start := time.Now()
	var err error
	for i := 0; i < 1000; i++ {
		_, err = cli.Write(data)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected write to fail with deadline")
	}
	t.Logf("write deadline hit in %v: %v", elapsed, err)
	if elapsed > 2*time.Second {
		t.Fatalf("took %v — deadline didn't fire", elapsed)
	}
}

func TestLargeReadWrite(t *testing.T) {
	cli, srv, cleanup := setupPair(t)
	defer cleanup()

	const size = 1 << 20 // 1MB
	sendBuf := make([]byte, size)
	rand.Read(sendBuf)

	errc := make(chan error, 1)
	go func() {
		_, err := srv.Write(sendBuf)
		errc <- err
	}()

	recvBuf := make([]byte, 0, size)
	tmp := make([]byte, 32768)
	for len(recvBuf) < size {
		n, err := cli.Read(tmp)
		if n > 0 {
			recvBuf = append(recvBuf, tmp[:n]...)
		}
		if err != nil {
			if err == io.EOF && len(recvBuf) == size {
				break
			}
			t.Fatalf("read after %d bytes: %v", len(recvBuf), err)
		}
	}

	if err := <-errc; err != nil {
		t.Fatalf("server write: %v", err)
	}

	if !bytes.Equal(sendBuf, recvBuf) {
		t.Fatalf("data mismatch: sent %d, received %d", len(sendBuf), len(recvBuf))
	}
	t.Logf("transferred %d bytes intact", size)
}

func TestConcurrentReadWrite(t *testing.T) {
	cli, srv, cleanup := setupPair(t)
	defer cleanup()

	if cli.sslWrite == cli.ssl {
		t.Skip("wolfSSL built without HAVE_WRITE_DUP; concurrent Read+Write serialized")
	}

	const messages = 100
	const msgSize = 512

	var wg sync.WaitGroup
	wg.Add(4)

	errs := make(chan error, 4)

	// Client writes to server
	go func() {
		defer wg.Done()
		for i := 0; i < messages; i++ {
			msg := bytes.Repeat([]byte{byte(i)}, msgSize)
			if _, err := cli.Write(msg); err != nil {
				errs <- fmt.Errorf("client write %d: %w", i, err)
				return
			}
		}
		errs <- nil
	}()

	// Server reads from client
	go func() {
		defer wg.Done()
		for i := 0; i < messages; i++ {
			buf := make([]byte, msgSize)
			total := 0
			for total < msgSize {
				n, err := srv.Read(buf[total:])
				if err != nil {
					errs <- fmt.Errorf("server read %d at %d: %w", i, total, err)
					return
				}
				total += n
			}
		}
		errs <- nil
	}()

	// Server writes to client
	go func() {
		defer wg.Done()
		for i := 0; i < messages; i++ {
			msg := bytes.Repeat([]byte{byte(i + 128)}, msgSize)
			if _, err := srv.Write(msg); err != nil {
				errs <- fmt.Errorf("server write %d: %w", i, err)
				return
			}
		}
		errs <- nil
	}()

	// Client reads from server
	go func() {
		defer wg.Done()
		for i := 0; i < messages; i++ {
			buf := make([]byte, msgSize)
			total := 0
			for total < msgSize {
				n, err := cli.Read(buf[total:])
				if err != nil {
					errs <- fmt.Errorf("client read %d at %d: %w", i, total, err)
					return
				}
				total += n
			}
		}
		errs <- nil
	}()

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("exchanged %d messages (%d bytes each) bidirectionally", messages, msgSize)
}

// clientAuthHandshake runs a server with the given ClientAuth and
// InsecureSkipVerify against a client that presents clientCert (nil for an
// anonymous client). It reports the server-side handshake error (nil means
// the client was accepted) and how many certificates the server saw.
func clientAuthHandshake(t *testing.T, auth ClientAuthType, insecure bool, clientCert *Certificate) (error, int) {
	t.Helper()

	srvCfg := &Config{
		Certificates: []Certificate{{
			CertPEM: loadFile(t, certPath("server-cert.pem")),
			KeyPEM:  loadFile(t, certPath("server-key.pem")),
		}},
		RootCAPEMs:         [][]byte{loadFile(t, certPath("ca-cert.pem"))},
		ClientAuth:         auth,
		InsecureSkipVerify: insecure,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		err       error
		peerCerts int
	}
	srvRes := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvRes <- result{err: err}
			return
		}
		defer conn.Close()
		s := Server(conn, srvCfg)
		defer s.Close()
		if err := s.Handshake(); err != nil {
			srvRes <- result{err: err}
			return
		}
		srvRes <- result{peerCerts: len(s.ConnectionState().PeerCertificates)}
	}()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	cliCfg := &Config{ServerName: "localhost", InsecureSkipVerify: true}
	if clientCert != nil {
		cliCfg.Certificates = []Certificate{*clientCert}
	}
	cli := Client(c, cliCfg)
	defer cli.Close()
	_ = cli.Handshake()

	res := <-srvRes
	return res.err, res.peerCerts
}

// clientAuthNoCertHandshake is clientAuthHandshake with an anonymous client.
func clientAuthNoCertHandshake(t *testing.T, auth ClientAuthType, insecure bool) error {
	t.Helper()
	err, _ := clientAuthHandshake(t, auth, insecure, nil)
	return err
}

// TestClientAuthNotRelaxedByInsecureSkipVerify checks that a server's
// mandatory-client-auth policy survives InsecureSkipVerify. Previously the
// verification-mode switch tested InsecureSkipVerify first, installing
// SSL_VERIFY_NONE, which on a server suppresses the CertificateRequest
// altogether and let anonymous clients complete the handshake.
func TestClientAuthNotRelaxedByInsecureSkipVerify(t *testing.T) {
	for _, auth := range []struct {
		name string
		val  ClientAuthType
	}{
		{"RequireAnyClientCert", RequireAnyClientCert},
		{"RequireAndVerifyClientCert", RequireAndVerifyClientCert},
	} {
		for _, insecure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/InsecureSkipVerify=%v", auth.name, insecure), func(t *testing.T) {
				err := clientAuthNoCertHandshake(t, auth.val, insecure)
				if err == nil {
					t.Fatal("server completed the handshake with a client that presented no certificate")
				}
				t.Logf("rejected as expected: %v", err)
			})
		}
	}
}

// TestUnknownClientAuthFailsClosed covers a ClientAuth value outside the
// defined set. It reaches the server branch (it is != NoClientCert) but
// matches no case in the inner switch, so it lands on the seeded mode.
// That seed must be SSL_VERIFY_PEER: seeded with SSL_VERIFY_NONE the server
// sent no CertificateRequest, silently disabling client auth for what is
// most likely a caller bug.
func TestUnknownClientAuthFailsClosed(t *testing.T) {
	// server-cert/key doubles as a client identity here: it chains to
	// ca-cert.pem, which is what the server loads as RootCAPEMs, so the
	// handshake completes and any failure is about the CertificateRequest
	// rather than an unrelated verification error.
	clientCert := &Certificate{
		CertPEM: loadFile(t, certPath("server-cert.pem")),
		KeyPEM:  loadFile(t, certPath("server-key.pem")),
	}
	err, peerCerts := clientAuthHandshake(t, ClientAuthType(99), false, clientCert)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if peerCerts == 0 {
		t.Fatal("server sent no CertificateRequest for an unknown ClientAuth value; client auth was silently disabled")
	}
	t.Logf("unknown ClientAuth requested a client certificate as expected: peerCerts=%d", peerCerts)
}

// foreignClientCert returns a self-signed certificate and key, i.e. an
// identity that chains to nothing the server trusts.
func foreignClientCert(t *testing.T) *Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unaffiliated client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return &Certificate{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// TestNoClientCertRequestsNothing pins NoClientCert to crypto/tls semantics:
// "no client certificate should be requested during the handshake, and if
// any certificates are sent they will not be verified". NoClientCert used to
// fall through to SSL_VERIFY_PEER, so the server solicited a certificate it
// had declared no interest in and then killed the handshake over a chain it
// could not validate -- rejecting, on client-auth grounds, a client of a
// server that does no client auth.
func TestNoClientCertRequestsNothing(t *testing.T) {
	for _, tc := range []struct {
		name       string
		clientCert *Certificate
	}{
		{"anonymous client", nil},
		{"client offering an untrusted cert", foreignClientCert(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err, peerCerts := clientAuthHandshake(t, NoClientCert, false, tc.clientCert)
			if err != nil {
				t.Fatalf("server rejected the client under NoClientCert: %v", err)
			}
			if peerCerts != 0 {
				t.Errorf("server collected %d peer certificates under NoClientCert; it should not have asked", peerCerts)
			}
		})
	}
}
