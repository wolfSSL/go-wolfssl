/* interop_test.go
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

const interopHost = "interop.test"

// interopPKI is a CA and a server certificate for interopHost, generated
// with crypto/x509 so both TLS stacks load the same identity.
type interopPKI struct {
	caPEM, certPEM, keyPEM []byte
	stdCert                tls.Certificate
	pool                   *x509.CertPool
}

func newInteropPKI(t *testing.T) *interopPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "interop CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: interopHost},
		DNSNames:     []string{interopHost},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := &interopPKI{
		caPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pool:    x509.NewCertPool(),
	}
	p.pool.AddCert(ca)
	if p.stdCert, err = tls.X509KeyPair(p.certPEM, p.keyPEM); err != nil {
		t.Fatal(err)
	}
	return p
}

// skipIfUnsupported skips when err says this wolfSSL build lacks a feature
// the case needs; any other error is a real failure. CI sets
// WOLFTLS_INTEROP_STRICT for full-featured builds, where nothing may skip.
func skipIfUnsupported(t *testing.T, err error) {
	t.Helper()
	if err == nil || os.Getenv("WOLFTLS_INTEROP_STRICT") != "" {
		return
	}
	msg := err.Error()
	for _, s := range []string{"(-174)", "requires wolfSSL built with", "proto_version"} {
		if strings.Contains(msg, s) {
			t.Skipf("not supported by this wolfSSL build: %v", err)
		}
	}
}

// interopCase pins a TLS version and offers ALPN; the zero case uses each
// stack's defaults so builds without either still interoperate.
type interopCase struct {
	name    string
	version uint16
	alpn    bool
}

var interopCases = []interopCase{
	{"defaults", 0, false},
	{"TLS 1.0", VersionTLS10, false},
	{"TLS 1.2 with ALPN", VersionTLS12, true},
	{"TLS 1.3 with ALPN", VersionTLS13, true},
}

// skipLegacy skips the TLS 1.0 case unless CI marks the build as having it.
func (c interopCase) skipLegacy(t *testing.T) {
	t.Helper()
	if c.version == VersionTLS10 && os.Getenv("WOLFTLS_INTEROP_TLS10") == "" {
		t.Skip("TLS 1.0 runs only against the oldtls wolfSSL build")
	}
}

func (c interopCase) protos(p ...string) []string {
	if c.alpn {
		return p
	}
	return nil
}

func (c interopCase) checkState(t *testing.T, clientVer, serverVer uint16, clientProto, serverProto string) {
	t.Helper()
	want := c.version
	if want == 0 && clientVer < VersionTLS12 {
		t.Errorf("negotiated version %#x, want TLS 1.2 or later", clientVer)
	}
	if want != 0 && clientVer != want {
		t.Errorf("client version %#x, want %#x", clientVer, want)
	}
	if clientVer != serverVer {
		t.Errorf("client version %#x, server version %#x", clientVer, serverVer)
	}
	wantProto := ""
	if c.alpn {
		wantProto = "h2"
	}
	if clientProto != wantProto || serverProto != wantProto {
		t.Errorf("ALPN client %q server %q, want %q", clientProto, serverProto, wantProto)
	}
}

type interopResult struct {
	state tls.ConnectionState
	got   string
	err   error
}

// echoStd runs a crypto/tls server that echoes one line.
func echoStd(t *testing.T, cfg *tls.Config) (string, <-chan interopResult) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan interopResult, 1)
	go func() {
		defer ln.Close()
		raw, err := ln.Accept()
		if err != nil {
			done <- interopResult{err: err}
			return
		}
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		srv := tls.Server(raw, cfg)
		defer srv.Close()
		var r interopResult
		if r.err = srv.Handshake(); r.err == nil {
			buf := make([]byte, 4)
			if _, r.err = io.ReadFull(srv, buf); r.err == nil {
				r.got = string(buf)
				_, r.err = srv.Write(buf)
			}
		}
		r.state = srv.ConnectionState()
		done <- r
	}()
	return ln.Addr().String(), done
}

func TestInteropWolftlsClientStdlibServer(t *testing.T) {
	pki := newInteropPKI(t)
	for _, c := range interopCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			c.skipLegacy(t)
			addr, done := echoStd(t, &tls.Config{
				Certificates: []tls.Certificate{pki.stdCert},
				MinVersion:   c.version,
				MaxVersion:   c.version,
				NextProtos:   c.protos("h2", "http/1.1"),
			})
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			cli := Client(raw, &Config{
				ServerName: interopHost,
				RootCAPEMs: [][]byte{pki.caPEM},
				MinVersion: c.version,
				MaxVersion: c.version,
				NextProtos: c.protos("h2"),
			})
			defer cli.Close()
			cli.SetDeadline(time.Now().Add(10 * time.Second))
			err = cli.Handshake()
			skipIfUnsupported(t, err)
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if _, err := cli.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(cli, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("echo %q: %v", buf, err)
			}
			r := <-done
			if r.err != nil {
				t.Fatalf("server: %v", r.err)
			}
			cs := cli.ConnectionState()
			c.checkState(t, cs.Version, r.state.Version, cs.NegotiatedProtocol, r.state.NegotiatedProtocol)
			if r.state.ServerName != interopHost {
				t.Errorf("server saw SNI %q, want %q", r.state.ServerName, interopHost)
			}
		})
	}
}

func TestInteropStdlibClientWolftlsServer(t *testing.T) {
	pki := newInteropPKI(t)
	for _, c := range interopCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			c.skipLegacy(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			var srvState ConnectionState
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				srv := Server(raw, &Config{
					Certificates: []Certificate{{CertPEM: pki.certPEM, KeyPEM: pki.keyPEM}},
					MinVersion:   c.version,
					MaxVersion:   c.version,
					NextProtos:   c.protos("h2", "http/1.1"),
				})
				defer srv.Close()
				srv.SetDeadline(time.Now().Add(10 * time.Second))
				if err := srv.Handshake(); err != nil {
					done <- err
					return
				}
				buf := make([]byte, 4)
				_, err = io.ReadFull(srv, buf)
				if err == nil {
					_, err = srv.Write(buf)
				}
				srvState = srv.ConnectionState()
				done <- err
			}()
			cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
				ServerName: interopHost,
				RootCAs:    pki.pool,
				MinVersion: c.version,
				MaxVersion: c.version,
				NextProtos: c.protos("h2"),
			})
			if err != nil {
				srvErr := <-done
				skipIfUnsupported(t, srvErr)
				t.Fatalf("handshake: client %v, server %v", err, srvErr)
			}
			defer cli.Close()
			cli.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := cli.Write([]byte("pong")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(cli, buf); err != nil || string(buf) != "pong" {
				t.Fatalf("echo %q: %v", buf, err)
			}
			if err := <-done; err != nil {
				t.Fatalf("server: %v", err)
			}
			cs := cli.ConnectionState()
			c.checkState(t, cs.Version, srvState.Version, cs.NegotiatedProtocol, srvState.NegotiatedProtocol)
		})
	}
}

func TestInteropRejectsBadPeer(t *testing.T) {
	pki, other := newInteropPKI(t), newInteropPKI(t)
	for name, cfg := range map[string]*Config{
		"wrong hostname": {ServerName: "other.test", RootCAPEMs: [][]byte{pki.caPEM}},
		"untrusted CA":   {ServerName: interopHost, RootCAPEMs: [][]byte{other.caPEM}},
	} {
		cfg := cfg
		t.Run(name, func(t *testing.T) {
			addr, done := echoStd(t, &tls.Config{Certificates: []tls.Certificate{pki.stdCert}})
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			cli := Client(raw, cfg)
			cli.SetDeadline(time.Now().Add(10 * time.Second))
			err = cli.Handshake()
			cli.Close()
			<-done
			if err == nil {
				t.Fatal("wolftls client accepted a server it should reject")
			}
		})
	}

	t.Run("stdlib rejects untrusted wolftls server", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			srv := Server(raw, &Config{
				Certificates: []Certificate{{CertPEM: pki.certPEM, KeyPEM: pki.keyPEM}},
			})
			srv.SetDeadline(time.Now().Add(10 * time.Second))
			srv.Handshake()
			srv.Close()
		}()
		cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName: interopHost,
			RootCAs:    other.pool,
		})
		if err == nil {
			cli.Close()
			t.Fatal("crypto/tls accepted a wolftls server signed by an untrusted CA")
		}
	})
}
