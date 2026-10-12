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
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
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

func TestRepeatedCertSetupInstallsStaticOnNil(t *testing.T) {
	ctx := wolfSSL.WolfSSL_CTX_new(wolfSSL.WolfSSLv23_server_method())
	if ctx == nil {
		t.Fatal("WolfSSL_CTX_new failed")
	}
	defer wolfSSL.WolfSSL_CTX_free(ctx)
	chain := newTestChain(t, nil)
	if wolfSSL.WolfSSL_CTX_use_certificate_chain_buffer_format(ctx, chain.leafDER, len(chain.leafDER),
		wolfSSL.SSL_FILETYPE_ASN1) != wolfSSL.WOLFSSL_SUCCESS ||
		wolfSSL.WolfSSL_CTX_use_PrivateKey_buffer(ctx, chain.keyDER, len(chain.keyDER),
			wolfSSL.SSL_FILETYPE_ASN1) != wolfSSL.WOLFSSL_SUCCESS {
		t.Fatal("loading the CTX certificate failed")
	}
	ssl := wolfSSL.WolfSSL_new(ctx)
	if ssl == nil {
		t.Fatal("WolfSSL_new failed")
	}
	defer wolfSSL.WolfSSL_free(ssl)

	static, dynamic := &Certificate{KeyDER: []byte("static")}, &Certificate{KeyDER: []byte("dynamic")}
	results := []*Certificate{dynamic, nil}
	var installed []*Certificate
	var cbErr error
	getCert := func(*ClientHelloInfo) (*Certificate, error) {
		r := results[0]
		results = results[1:]
		return r, nil
	}
	install := func(_ *wolfSSL.WOLFSSL, c *Certificate) bool {
		installed = append(installed, c)
		return true
	}
	for i := 0; i < 2; i++ {
		if !selectCertificate(ssl, getCert, static, install, &cbErr) {
			t.Fatalf("call %d failed: %v", i, cbErr)
		}
	}
	if len(installed) != 2 || installed[0] != dynamic || installed[1] != static {
		t.Fatalf("installed %v, want the dynamic then the static certificate", installed)
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

func legacyOnly(cfg *Config) *Config {
	cfg.MinVersion = VersionTLS11
	cfg.MaxVersion = VersionTLS11
	return cfg
}

func TestZeroMinVersionRefusesLegacyTLS(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))
	server := func() *Config {
		return &Config{Certificates: []Certificate{{CertPEM: certPEM, KeyPEM: keyPEM}}}
	}
	client := func() *Config { return &Config{InsecureSkipVerify: true} }

	probe := runHandshake(t, legacyOnly(server()), legacyOnly(client()))
	if probe.clientErr != nil || probe.serverErr != nil || probe.client.Version != VersionTLS11 {
		t.Skipf("wolfSSL cannot negotiate TLS 1.1: client %v, server %v", probe.clientErr, probe.serverErr)
	}

	t.Run("server", func(t *testing.T) {
		res := runHandshake(t, server(), legacyOnly(client()))
		if res.serverErr == nil {
			t.Fatalf("server with zero MinVersion accepted version 0x%x", res.server.Version)
		}
	})
	t.Run("client", func(t *testing.T) {
		res := runHandshake(t, legacyOnly(server()), client())
		if res.clientErr == nil {
			t.Fatalf("client with zero MinVersion accepted version 0x%x", res.client.Version)
		}
	})
}

func TestExplicitMinVersionKeepsLegacyTLS(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))
	serverCfg := legacyOnly(&Config{Certificates: []Certificate{{CertPEM: certPEM, KeyPEM: keyPEM}}})
	res := runHandshake(t, serverCfg, legacyOnly(&Config{InsecureSkipVerify: true}))
	if res.clientErr != nil && (strings.Contains(res.clientErr.Error(), "proto_version") ||
		strings.Contains(res.clientErr.Error(), "requires wolfSSL built with OPENSSL_EXTRA")) {
		t.Skipf("wolfSSL built without TLS 1.1: %v", res.clientErr)
	}
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("explicit TLS 1.1 handshake: client %v, server %v", res.clientErr, res.serverErr)
	}
	if res.client.Version != VersionTLS11 {
		t.Fatalf("negotiated 0x%x, want TLS 1.1", res.client.Version)
	}
}

func TestIPServerNameNotSentAsSNI(t *testing.T) {
	certPEM := loadFile(t, certPath("server-cert.pem"))
	keyPEM := loadFile(t, certPath("server-key.pem"))
	for _, name := range []string{"127.0.0.1", "::1", "[::1]"} {
		t.Run(name, func(t *testing.T) {
			serverCfg := &Config{Certificates: []Certificate{{CertPEM: certPEM, KeyPEM: keyPEM}}}
			res := runHandshake(t, serverCfg, &Config{ServerName: name, InsecureSkipVerify: true})
			if res.clientErr != nil || res.serverErr != nil {
				t.Fatalf("handshake: client %v, server %v", res.clientErr, res.serverErr)
			}
			if res.server.ServerName != "" {
				t.Fatalf("server received SNI %q for an IP literal", res.server.ServerName)
			}
			if res.client.ServerName != "" {
				t.Fatalf("client reports SNI %q for an IP literal", res.client.ServerName)
			}
		})
	}
}

func TestIPServerNameVerifiesIPSAN(t *testing.T) {
	ipChain := newTestChain(t, func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	})
	dnsChain := newTestChain(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"127.0.0.1"}
	})
	otherIPChain := newTestChain(t, func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = []net.IP{net.ParseIP("127.0.0.2")}
	})
	cnOnly := func(cn string) testChain {
		return newTestChain(t, func(c *x509.Certificate) {
			c.DNSNames = nil
			c.Subject.CommonName = cn
		})
	}
	cnV4Chain := cnOnly("127.0.0.1")
	cnV6Chain := cnOnly("0000:0000:0000:0000:0000:0000:0000:0001")
	cnV6ShortChain := cnOnly("::1")
	mappedChain := newTestChain(t, func(c *x509.Certificate) {
		c.DNSNames = nil
		san, err := asn1.Marshal([]asn1.RawValue{{
			Class: asn1.ClassContextSpecific,
			Tag:   7,
			Bytes: net.ParseIP("127.0.0.1").To16(),
		}})
		if err != nil {
			t.Fatalf("SAN: %v", err)
		}
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}
	})
	server := func(ch testChain) *Config {
		return &Config{Certificates: []Certificate{{
			CertDER: [][]byte{ch.leafDER, ch.interDER},
			KeyDER:  ch.keyDER,
		}}}
	}
	client := func(ch testChain, name string) *Config {
		return &Config{ServerName: name, RootCAPEMs: [][]byte{ch.rootPEM}}
	}
	var major, minor, patch int
	fmt.Sscanf(wolfSSL.WolfSSL_lib_version(), "%d.%d.%d", &major, &minor, &patch)
	cnSafeIPCheck := major*1000000+minor*1000+patch >= 5009002

	for _, tc := range []struct {
		name   string
		chain  testChain
		server string
		ok     bool
	}{
		{"ipv4 SAN", ipChain, "127.0.0.1", true},
		{"ipv6 SAN", ipChain, "::1", true},
		{"ipv6 SAN bracketed", ipChain, "[::1]", true},
		{"ipv6 SAN scoped", ipChain, "::1%lo", true},
		{"ipv4-mapped scoped", ipChain, "::ffff:127.0.0.1%lo", true},
		// RFC 5280 encodes an IPv4 iPAddress SAN in four octets only.
		{"ipv4 vs 16-byte mapped SAN", mappedChain, "127.0.0.1", false},
		{"mapped vs 16-byte mapped SAN", mappedChain, "::ffff:127.0.0.1", false},
		{"ipv4 with zone", ipChain, "127.0.0.1%lo", false},
		{"ipv6 empty zone", ipChain, "::1%", false},
		{"DNS SAN only", dnsChain, "127.0.0.1", false},
		{"other IP SAN", otherIPChain, "127.0.0.1", false},
		{"ipv4 CN only", cnV4Chain, "127.0.0.1", false},
		{"ipv6 CN only", cnV6Chain, "::1", false},
		{"ipv6 CN only bracketed", cnV6Chain, "[::1]", false},
		{"ipv6 CN only scoped", cnV6Chain, "::1%lo", false},
		{"ipv6 short CN only", cnV6ShortChain, "::1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := runHandshake(t, server(tc.chain), client(tc.chain, tc.server))
			if res.clientErr != nil && strings.Contains(res.clientErr.Error(), "wolfSSL 5.9.2 or later") && cnSafeIPCheck {
				t.Fatalf("wolfSSL %s should support IP checks: %v", wolfSSL.WolfSSL_lib_version(), res.clientErr)
			}
			if res.clientErr != nil && strings.Contains(res.clientErr.Error(), "verifying an IP ServerName requires") {
				if !tc.ok {
					return
				}
				t.Skip(res.clientErr)
			}
			if tc.ok && res.clientErr != nil {
				t.Fatalf("handshake failed: client %v, server %v", res.clientErr, res.serverErr)
			}
			if !tc.ok && (res.clientErr == nil || res.serverErr == nil) {
				t.Fatalf("certificate without a matching IP SAN: client %v, server %v",
					res.clientErr, res.serverErr)
			}
		})
	}
}

func TestGetCertificateErrorIsReturned(t *testing.T) {
	skipWithoutGetCertificate(t)
	chain := newTestChain(t, nil)
	errNoHost := errors.New("no certificate for host")
	serverCfg := &Config{
		Certificates: []Certificate{{
			CertDER: [][]byte{chain.leafDER, chain.interDER},
			KeyDER:  chain.keyDER,
		}},
		GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
			return nil, errNoHost
		},
	}
	res := runHandshake(t, serverCfg, &Config{ServerName: "chain.test", InsecureSkipVerify: true})
	if res.clientErr == nil {
		t.Fatal("client handshake succeeded")
	}
	if !errors.Is(res.serverErr, errNoHost) {
		t.Fatalf("server error %v does not wrap the GetCertificate error", res.serverErr)
	}
}

func TestCipherSuitesRejectsUnencodableEntries(t *testing.T) {
	const suite = "TLS13-AES128-GCM-SHA256"
	for name, suites := range map[string][]string{
		"nul":   {suite + "\x00ECDHE-RSA-NULL-SHA"},
		"empty": {suite, ""},
	} {
		t.Run(name, func(t *testing.T) {
			configRejected(t, &Config{InsecureSkipVerify: true, CipherSuites: suites}, true)
		})
	}
}
