/* config_test.go
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
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

type testChain struct {
	rootPEM  []byte
	interDER []byte
	leafDER  []byte
	keyDER   []byte
}

// newTestChain issues root -> intermediate -> leaf. leaf customizes the
// leaf template (SANs) before signing.
func newTestChain(t *testing.T, leaf func(*x509.Certificate)) testChain {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		return k
	}
	now := time.Now()
	rootKey, interKey, leafKey := newKey(), newKey(), newKey()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wolftls test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(crand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "wolftls test intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(crand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "wolftls test leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"chain.test"},
	}
	if leaf != nil {
		leaf(leafTmpl)
	}
	leafDER, err := x509.CreateCertificate(crand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return testChain{
		rootPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		interDER: interDER,
		leafDER:  leafDER,
		keyDER:   keyDER,
	}
}

type handshakeResult struct {
	client, server       ConnectionState
	clientErr, serverErr error
}

// runHandshake connects a Client and Server over loopback TCP and returns
// both sides' states and errors.
func runHandshake(t *testing.T, serverCfg, clientCfg *Config) handshakeResult {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type srvOut struct {
		state ConnectionState
		err   error
	}
	done := make(chan srvOut, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- srvOut{err: err}
			return
		}
		srv := Server(conn, serverCfg)
		defer srv.Close()
		srv.SetDeadline(time.Now().Add(10 * time.Second))
		err = srv.Handshake()
		done <- srvOut{state: srv.ConnectionState(), err: err}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cli := Client(conn, clientCfg)
	cli.SetDeadline(time.Now().Add(10 * time.Second))
	var res handshakeResult
	res.clientErr = cli.Handshake()
	res.client = cli.ConnectionState()
	if res.clientErr != nil {
		cli.Close()
	}
	out := <-done
	if res.clientErr == nil {
		cli.Close()
	}
	res.server, res.serverErr = out.state, out.err
	return res
}

// skipWithoutGetCertificate skips when this wolfSSL build cannot run
// GetCertificate (no WOLFSSL_CERT_SETUP_CB).
func skipWithoutGetCertificate(t *testing.T) {
	t.Helper()
	chain := newTestChain(t, nil)
	cert := Certificate{CertDER: [][]byte{chain.leafDER, chain.interDER}, KeyDER: chain.keyDER}
	called := make(chan struct{}, 1)
	serverCfg := &Config{
		Certificates: []Certificate{cert},
		GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
			select {
			case called <- struct{}{}:
			default:
			}
			return &cert, nil
		},
	}
	res := runHandshake(t, serverCfg, &Config{ServerName: "chain.test", RootCAPEMs: [][]byte{chain.rootPEM}})
	select {
	case <-called:
	default:
		t.Skipf("GetCertificate unavailable in this wolfSSL build: client %v, server %v", res.clientErr, res.serverErr)
	}
}

func TestDERCertificateChainSendsIntermediates(t *testing.T) {
	chain := newTestChain(t, nil)
	derCert := Certificate{
		CertDER: [][]byte{chain.leafDER, chain.interDER},
		KeyDER:  chain.keyDER,
	}
	clientCfg := &Config{
		ServerName: "chain.test",
		RootCAPEMs: [][]byte{chain.rootPEM},
	}

	// The client trusts only the root, so a handshake succeeds only when the
	// server sent the intermediate.
	t.Run("static", func(t *testing.T) {
		res := runHandshake(t, &Config{Certificates: []Certificate{derCert}}, clientCfg)
		if res.clientErr != nil || res.serverErr != nil {
			t.Fatalf("handshake: client %v, server %v", res.clientErr, res.serverErr)
		}
	})

	t.Run("GetCertificate", func(t *testing.T) {
		skipWithoutGetCertificate(t)
		other := newTestChain(t, nil)
		serverCfg := &Config{
			Certificates: []Certificate{{
				CertDER: [][]byte{other.leafDER},
				KeyDER:  other.keyDER,
			}},
			GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
				c := derCert
				return &c, nil
			},
		}
		res := runHandshake(t, serverCfg, clientCfg)
		if res.clientErr != nil || res.serverErr != nil {
			t.Fatalf("handshake: client %v, server %v", res.clientErr, res.serverErr)
		}
	})
}

func TestGetCertificateNilFallsBackToStatic(t *testing.T) {
	skipWithoutGetCertificate(t)
	chain := newTestChain(t, nil)
	called := make(chan struct{}, 1)
	serverCfg := &Config{
		Certificates: []Certificate{{
			CertDER: [][]byte{chain.leafDER, chain.interDER},
			KeyDER:  chain.keyDER,
		}},
		GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
			called <- struct{}{}
			return nil, nil
		},
	}
	clientCfg := &Config{
		ServerName: "chain.test",
		RootCAPEMs: [][]byte{chain.rootPEM},
	}
	res := runHandshake(t, serverCfg, clientCfg)
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("handshake: client %v, server %v", res.clientErr, res.serverErr)
	}
	select {
	case <-called:
	default:
		t.Fatal("GetCertificate was not called")
	}
}

func TestGetCertificateNilWithoutStaticFails(t *testing.T) {
	serverCfg := &Config{
		GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
			return nil, nil
		},
	}
	res := runHandshake(t, serverCfg, &Config{InsecureSkipVerify: true})
	if res.serverErr == nil || res.clientErr == nil {
		t.Fatalf("handshake without any certificate succeeded: client %v, server %v",
			res.clientErr, res.serverErr)
	}
}

// untouchedConn fails every transport operation and records whether the
// handshake tried to use it.
type untouchedConn struct {
	net.Conn
	used bool
}

func (u *untouchedConn) Read([]byte) (int, error) {
	u.used = true
	return 0, errors.New("transport used")
}
func (u *untouchedConn) Write([]byte) (int, error) {
	u.used = true
	return 0, errors.New("transport used")
}
func (u *untouchedConn) Close() error { return nil }

// configRejected runs a handshake that must fail on configuration alone,
// before any byte reaches the transport.
func configRejected(t *testing.T, cfg *Config, isClient bool) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	u := &untouchedConn{Conn: a}
	var c *Conn
	if isClient {
		c = Client(u, cfg)
	} else {
		c = Server(u, cfg)
	}
	defer c.Close()
	err := c.Handshake()
	if err == nil {
		t.Fatal("handshake succeeded")
	}
	if u.used {
		t.Fatalf("invalid config reached the transport: %v", err)
	}
}

func TestNextProtosRejectsUnencodableEntries(t *testing.T) {
	for name, protos := range map[string][]string{
		"comma":    {"h2,http/1.1"},
		"nul":      {"h2\x00x"},
		"empty":    {"h2", ""},
		"too-long": {strings.Repeat("a", 256)},
	} {
		t.Run(name, func(t *testing.T) {
			configRejected(t, &Config{InsecureSkipVerify: true, NextProtos: protos}, true)
		})
	}
}

// TestMissingPeerChainFailsBeforeCallbacks checks that a session with no
// retrievable peer certificate is rejected before the verification
// callbacks would see an empty chain.
func TestMissingPeerChainFailsBeforeCallbacks(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cfg := &Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: func([][]byte) error { return nil },
	}
	c := newConn(a, cfg, true)
	c.ctx = wolfSSL.WolfSSL_CTX_new_v23_client()
	if c.ctx == nil {
		t.Fatal("CTX_new failed")
	}
	c.ssl = wolfSSL.WolfSSL_new(c.ctx)
	if c.ssl == nil {
		c.freeSSL()
		t.Fatal("WolfSSL_new failed")
	}
	defer c.freeSSL()

	if err := c.buildConnectionState(); err == nil {
		t.Fatal("empty peer chain accepted")
	}
	st := c.ConnectionState()
	if st.HandshakeComplete || st.Version != 0 || st.CipherSuite != "" ||
		st.ServerName != "" || st.NegotiatedProtocol != "" || st.PeerCertificates != nil {
		t.Fatalf("failed handshake left connection state %+v", st)
	}
}
