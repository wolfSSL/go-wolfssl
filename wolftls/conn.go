/* conn.go
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

// #cgo CFLAGS: -g -Wall -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// recordingConn wraps the underlying net.Conn so wolftls.Conn.Read can
// recover the original Go-side Read error after wolfSSL has reduced it to
// an error code. net/http's hijack-via-SetReadDeadline path expects Read to
// return a net.Error with Timeout()==true (server.go:backgroundRead /
// handleReadErrorLocked); collapsing that to a wolfSSL error string caused
// the DERP reconnect loop fixed alongside this type.
type recordingConn struct {
	net.Conn
	mu          sync.Mutex
	lastReadErr error
}

func (r *recordingConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if err != nil {
		r.mu.Lock()
		r.lastReadErr = err
		r.mu.Unlock()
	}
	return n, err
}

func (r *recordingConn) takeLastReadErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.lastReadErr
	r.lastReadErr = nil
	return err
}

// Conn is a TLS connection backed by wolfSSL. It implements net.Conn.
type Conn struct {
	conn     net.Conn
	config   *Config
	isClient bool

	// handshake state
	handshakeMu   sync.Mutex
	handshakeDone bool
	handshakeErr  error

	// mu protects c.ssl and c.ctx for callers that may run concurrently
	// with Close (e.g. http.Hijacker handing the conn to a DERP handler
	// while the HTTP server separately triggers shutdown). Read/Write
	// acquire RLock; Close acquires Lock after kicking in-flight I/O via
	// a past deadline on c.conn.
	mu sync.RWMutex

	// muRead/muWrite serialize wolfSSL_read/wolfSSL_write. Aliased to the
	// same mutex when HAVE_WRITE_DUP unavailable.
	muRead  *sync.Mutex
	muWrite *sync.Mutex

	// wolfSSL objects — created during handshake
	ctx      *wolfSSL.WOLFSSL_CTX
	ssl      *wolfSSL.WOLFSSL
	sslWrite *wolfSSL.WOLFSSL // == ssl when HAVE_WRITE_DUP unavailable

	// callback registration IDs (0 = none)
	ioConnID      int
	certCbID int

	// populated after handshake
	connState ConnectionState
}

func newConn(conn net.Conn, config *Config, isClient bool) *Conn {
	if config == nil {
		config = &Config{}
	}
	c := &Conn{
		conn:     &recordingConn{Conn: conn},
		config:   config.Clone(),
		isClient: isClient,
	}
	runtime.SetFinalizer(c, (*Conn).finalize)
	return c
}

func (c *Conn) finalize() { c.freeSSL() }

// Handshake performs the TLS handshake if it has not already been performed.
// It is safe to call concurrently; only the first call performs the handshake.
func (c *Conn) Handshake() error {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()

	if c.handshakeDone {
		return c.handshakeErr
	}

	c.handshakeErr = c.doHandshake()
	c.handshakeDone = true
	return c.handshakeErr
}

// HandshakeContext performs the TLS handshake, respecting context cancellation.
// If the context is canceled before the handshake completes, a past deadline
// is set on the underlying connection to unblock the wolfSSL handshake call.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	done := make(chan struct{})
	var err error
	go func() {
		err = c.Handshake()
		close(done)
	}()

	select {
	case <-done:
		return err
	case <-ctx.Done():
		// Set an expired deadline to unblock the blocking wolfSSL call
		// without closing the conn out from under the handshake goroutine.
		c.conn.SetDeadline(time.Unix(1, 0))
		<-done // wait for Handshake goroutine to finish
		// Restore deadline so the caller can still close cleanly.
		c.conn.SetDeadline(time.Time{})
		if err == nil {
			err = ctx.Err()
		}
		return err
	}
}

// doHandshake performs the actual handshake. Must be called with handshakeMu held.
func (c *Conn) doHandshake() error {
	// Reject a ServerName containing a NUL byte
	if strings.IndexByte(c.config.ServerName, 0) >= 0 {
		return errors.New("wolftls: ServerName contains NUL byte")
	}

	// Create CTX with version-flexible method
	if c.isClient {
		c.ctx = wolfSSL.WolfSSL_CTX_new_v23_client()
	} else {
		c.ctx = wolfSSL.WolfSSL_CTX_new_v23_server()
	}
	if c.ctx == nil {
		return errors.New("wolftls: failed to create WOLFSSL_CTX")
	}

	// Install Go I/O callbacks so wolfSSL reads/writes through net.Conn
	ctxSetIOCallbacks(c.ctx)

	// Set min/max TLS version.
	// wolfSSL_CTX_set_min/max_proto_version uses the same 0x0301-0x0304
	// constants as our VersionTLS* values. Check the return so a
	// rejected version (wolfSSL built without that version's support)
	// fails loudly instead of silently degrading policy.
	if c.config.MinVersion != 0 {
		if ret := wolfSSL.WolfSSL_CTX_set_min_proto_version(c.ctx, int(c.config.MinVersion)); ret != wolfSSL.WOLFSSL_SUCCESS {
			c.freeCtxLocked()
			return fmt.Errorf("wolftls: set_min_proto_version(0x%x) rejected: %d", c.config.MinVersion, ret)
		}
	}
	if c.config.MaxVersion != 0 {
		if ret := wolfSSL.WolfSSL_CTX_set_max_proto_version(c.ctx, int(c.config.MaxVersion)); ret != wolfSSL.WOLFSSL_SUCCESS {
			c.freeCtxLocked()
			return fmt.Errorf("wolftls: set_max_proto_version(0x%x) rejected: %d", c.config.MaxVersion, ret)
		}
	}

	// Configure verification mode. Server-side ClientAuth takes
	// precedence over the default SSL_VERIFY_PEER so a server can
	// require (or reject) client certificates. On client side or when
	// ClientAuth is unset, fall back to SSL_VERIFY_PEER / NONE as before.
	switch {
	case c.config.InsecureSkipVerify:
		wolfSSL.WolfSSL_CTX_set_verify(c.ctx, wolfSSL.SSL_VERIFY_NONE)
	case !c.isClient && c.config.ClientAuth != NoClientCert:
		mode := wolfSSL.SSL_VERIFY_NONE
		switch c.config.ClientAuth {
		case RequestClientCert, VerifyClientCertIfGiven:
			mode = wolfSSL.SSL_VERIFY_PEER
		case RequireAnyClientCert, RequireAndVerifyClientCert:
			mode = wolfSSL.SSL_VERIFY_PEER | wolfSSL.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		}
		wolfSSL.WolfSSL_CTX_set_verify(c.ctx, mode)
	default:
		wolfSSL.WolfSSL_CTX_set_verify(c.ctx, wolfSSL.SSL_VERIFY_PEER)
	}

	// Load root CA PEMs
	for _, pem := range c.config.RootCAPEMs {
		ret := wolfSSL.WolfSSL_CTX_load_verify_buffer(c.ctx, pem, len(pem),
			wolfSSL.SSL_FILETYPE_PEM)
		if ret != wolfSSL.WOLFSSL_SUCCESS {
			c.freeCtxLocked()
			return fmt.Errorf("wolftls: failed to load root CA PEM (%d)", ret)
		}
	}

	// Load certificates. Use the chain-buffer variant so any extra
	// CERTIFICATE blocks concatenated after the leaf (intermediates,
	// or protocol-specific markers like DERP's MetaCert) are sent to
	// the peer during the handshake. The single-cert _buffer variant
	// only parses the first PEM block and silently drops the rest.
	if len(c.config.Certificates) > 0 {
		cert := c.config.Certificates[0]
		if len(cert.CertPEM) > 0 {
			ret := wolfSSL.WolfSSL_CTX_use_certificate_chain_buffer_format(c.ctx, cert.CertPEM,
				len(cert.CertPEM), wolfSSL.SSL_FILETYPE_PEM)
			if ret != wolfSSL.WOLFSSL_SUCCESS {
				c.freeCtxLocked()
				return fmt.Errorf("wolftls: failed to load certificate chain (%d)", ret)
			}
		}
		if len(cert.KeyPEM) > 0 {
			ret := wolfSSL.WolfSSL_CTX_use_PrivateKey_buffer(c.ctx, cert.KeyPEM,
				len(cert.KeyPEM), wolfSSL.SSL_FILETYPE_PEM)
			if ret != wolfSSL.WOLFSSL_SUCCESS {
				c.freeCtxLocked()
				return fmt.Errorf("wolftls: failed to load private key (%d)", ret)
			}
		}
		if len(cert.CertDER) > 0 {
			ret := wolfSSL.WolfSSL_CTX_use_certificate_buffer(c.ctx, cert.CertDER[0],
				len(cert.CertDER[0]), wolfSSL.SSL_FILETYPE_ASN1)
			if ret != wolfSSL.WOLFSSL_SUCCESS {
				c.freeCtxLocked()
				return fmt.Errorf("wolftls: failed to load DER certificate (%d)", ret)
			}
		}
		if len(cert.KeyDER) > 0 {
			ret := wolfSSL.WolfSSL_CTX_use_PrivateKey_buffer(c.ctx, cert.KeyDER,
				len(cert.KeyDER), wolfSSL.SSL_FILETYPE_ASN1)
			if ret != wolfSSL.WOLFSSL_SUCCESS {
				c.freeCtxLocked()
				return fmt.Errorf("wolftls: failed to load DER private key (%d)", ret)
			}
		}
	}

	// Set up the cert-setup callback for per-connection cert/key install.
	//
	// The cert-setup callback fires AFTER wolfSSL parses the ClientHello
	// (so SNI + ALPN are available) and BEFORE wolfSSL's cert/key
	// availability check (which would otherwise reject lazy-cert listeners
	// with NO_PRIVATE_KEY). This is the right hook for autocert.Manager,
	// which only acquires a cert lazily on the first SNI hello.
	//
	// Compared with the SNI servername callback we used previously: the
	// SNI callback fires only when an SNI extension is present and runs
	// during extension parsing (before the cert/key check). The cert-setup
	// callback fires unconditionally on every server handshake, suppresses
	// the cert/key precondition check, and gives us a unified place to
	// resolve cert + key + ALPN in one pass.
	//
	// Requires wolfSSL built with WOLFSSL_CERT_SETUP_CB. To also support
	// listeners that have no static cert at construction time, wolfSSL
	// must be built with WOLFSSL_NO_INIT_CTX_KEY.
	if c.config.GetCertificate != nil && !c.isClient {
		getCert := c.config.GetCertificate
		c.certCbID = registerCertSetupCallback(func(ssl *wolfSSL.WOLFSSL) int {
			serverName := wolfSSL.WolfSSL_SNI_GetServerName(ssl)
			alpn, _ := wolfSSL.WolfSSL_ALPN_GetPeerProtocol(ssl)
			cert, err := getCert(&ClientHelloInfo{
				ServerName:      serverName,
				SupportedProtos: alpn,
			})
			if err != nil || cert == nil {
				return 0 // signal fatal alert per CertSetupCb contract
			}
			if len(cert.CertPEM) > 0 {
				ret := wolfSSL.WolfSSL_use_certificate_chain_buffer_format(ssl, cert.CertPEM,
					len(cert.CertPEM), wolfSSL.SSL_FILETYPE_PEM)
				if ret != wolfSSL.WOLFSSL_SUCCESS {
					return 0
				}
			}
			if len(cert.KeyPEM) > 0 {
				ret := wolfSSL.WolfSSL_use_PrivateKey_buffer(ssl, cert.KeyPEM,
					len(cert.KeyPEM), wolfSSL.SSL_FILETYPE_PEM)
				if ret != wolfSSL.WOLFSSL_SUCCESS {
					return 0
				}
			}
			if len(cert.CertDER) > 0 {
				ret := wolfSSL.WolfSSL_use_certificate_buffer(ssl, cert.CertDER[0],
					len(cert.CertDER[0]), wolfSSL.SSL_FILETYPE_ASN1)
				if ret != wolfSSL.WOLFSSL_SUCCESS {
					return 0
				}
			}
			if len(cert.KeyDER) > 0 {
				ret := wolfSSL.WolfSSL_use_PrivateKey_buffer(ssl, cert.KeyDER,
					len(cert.KeyDER), wolfSSL.SSL_FILETYPE_ASN1)
				if ret != wolfSSL.WOLFSSL_SUCCESS {
					return 0
				}
			}
			return 1 // success per CertSetupCb contract
		})
		ctxSetCertSetupCallback(c.ctx, c.certCbID)
	}

	// Set cipher suites
	if len(c.config.CipherSuites) > 0 {
		list := strings.Join(c.config.CipherSuites, ":")
		ret := wolfSSL.WolfSSL_CTX_set_cipher_list(c.ctx, list)
		if ret != wolfSSL.WOLFSSL_SUCCESS {
			c.freeCtxLocked()
			return fmt.Errorf("wolftls: failed to set cipher list (%d)", ret)
		}
	}

	// Create SSL session
	c.ssl = wolfSSL.WolfSSL_new(c.ctx)
	if c.ssl == nil {
		c.freeCtxLocked()
		return errors.New("wolftls: failed to create WOLFSSL session")
	}

	// Set SNI
	if c.config.ServerName != "" {
		sniData := []byte(c.config.ServerName)
		ret := wolfSSL.WolfSSL_UseSNI(c.ssl, wolfSSL.WOLFSSL_SNI_HOST_NAME,
			sniData, len(sniData))
		if ret != wolfSSL.WOLFSSL_SUCCESS {
			c.freeSSL()
			return fmt.Errorf("wolftls: failed to set SNI (%d)", ret)
		}
	}

	// Bind the expected hostname so wolfSSL checks the server leaf
	// certificate's SAN/CN against it during the handshake
	if c.isClient && c.config.ServerName != "" && !c.config.InsecureSkipVerify {
		ret := wolfSSL.WolfSSL_check_domain_name(c.ssl, c.config.ServerName)
		if ret != wolfSSL.WOLFSSL_SUCCESS {
			c.freeSSL()
			return fmt.Errorf("wolftls: failed to set domain name check (%d)", ret)
		}
	}

	// Set ALPN
	if len(c.config.NextProtos) > 0 {
		// wolfSSL expects a comma-separated list
		alpnList := strings.Join(c.config.NextProtos, ",")
		ret := wolfSSL.WolfSSL_UseALPN(c.ssl, alpnList,
			wolfSSL.WOLFSSL_ALPN_FAILED_ON_MISMATCH)
		if ret != wolfSSL.WOLFSSL_SUCCESS {
			c.freeSSL()
			return fmt.Errorf("wolftls: failed to set ALPN (%d)", ret)
		}
	}

	// Register net.Conn for I/O callbacks (no fd extraction needed)
	c.ioConnID = registerIOConn(c.conn)
	sslSetIOCtx(c.ssl, c.ioConnID)

	// Perform handshake
	var ret int
	if c.isClient {
		ret = wolfSSL.WolfSSL_connect(c.ssl)
	} else {
		ret = wolfSSL.WolfSSL_accept(c.ssl)
	}
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		errCode := wolfSSL.WolfSSL_get_error(c.ssl, ret)
		errMsg := wolfSSL.WolfSSL_ERR_error_string(errCode, nil)
		c.cleanup()
		return fmt.Errorf("wolftls: handshake failed: %s (%d)", errMsg, errCode)
	}

	// Build connection state
	if err := c.buildConnectionState(); err != nil {
		c.cleanup()
		return err
	}

	// Run verification callbacks
	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(c.connState.PeerCertificates); err != nil {
			c.cleanup()
			return err
		}
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connState); err != nil {
			c.cleanup()
			return err
		}
	}

	// Split off a write-only WOLFSSL when HAVE_WRITE_DUP is built in;
	// otherwise fall back to a single mutex serializing Read and Write.
	if dup := wolfSSL.WolfSSL_write_dup(c.ssl); dup != nil {
		c.sslWrite = dup
		c.muRead = &sync.Mutex{}
		c.muWrite = &sync.Mutex{}
	} else {
		c.sslWrite = c.ssl
		shared := &sync.Mutex{}
		c.muRead = shared
		c.muWrite = shared
	}

	return nil
}

// cleanup releases all wolfSSL resources and the I/O callback registration.
// Used on handshake failure so nothing leaks even if Close() is never called.
func (c *Conn) cleanup() {
	c.freeSSL()
}

// buildConnectionState populates c.connState from the wolfSSL session.
func (c *Conn) buildConnectionState() error {
	c.connState.HandshakeComplete = true
	if c.isClient {
		// Client: SNI is what we sent; mirror the value from config.
		c.connState.ServerName = c.config.ServerName
	} else {
		// Server: SNI is what the client sent in its ClientHello; query
		// the wolfSSL session. Required for server-side dispatch logic
		// that reads ConnectionState().ServerName (e.g., net/http's
		// r.TLS.ServerName, which downstream handlers use for per-host
		// routing).
		c.connState.ServerName = wolfSSL.WolfSSL_SNI_GetServerName(c.ssl)
	}

	// TLS version
	versionStr := wolfSSL.WolfSSL_get_version(c.ssl)
	c.connState.Version = parseVersion(versionStr)

	// Cipher suite
	c.connState.CipherSuite = wolfSSL.WolfSSL_get_cipher_name(c.ssl)

	// ALPN negotiated protocol
	proto, ret := wolfSSL.WolfSSL_ALPN_GetProtocol(c.ssl)
	if ret == wolfSSL.WOLFSSL_SUCCESS {
		c.connState.NegotiatedProtocol = proto
	}

	// Peer certificates
	c.extractPeerCerts()

	return nil
}

// extractPeerCerts retrieves the peer certificate chain from wolfSSL as
// DER-encoded byte slices. Must be called while c.ssl is still valid.
// The returned slices are Go-owned copies — safe to use after WolfSSL_free.
func (c *Conn) extractPeerCerts() {
	c.connState.PeerCertificates = wolfSSL.WolfSSL_get_peer_cert_chain_DER(c.ssl)
}

// ConnectionState returns the state of the TLS connection. If the handshake
// has not yet completed, it returns a zero-value ConnectionState.
func (c *Conn) ConnectionState() ConnectionState {
	return c.connState
}

// Read reads data from the TLS connection. If the handshake has not yet
// completed, it is performed first.
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ssl == nil {
		return 0, net.ErrClosed
	}
	c.muRead.Lock()
	defer c.muRead.Unlock()
	n := wolfSSL.WolfSSL_read(c.ssl, b, uintptr(len(b)))
	if n > 0 {
		return n, nil
	}
	if rc, ok := c.conn.(*recordingConn); ok {
		if e := rc.takeLastReadErr(); e != nil {
			return 0, e
		}
	}
	if n == 0 {
		return 0, io.EOF
	}
	errCode := wolfSSL.WolfSSL_get_error(c.ssl, n)
	errMsg := wolfSSL.WolfSSL_ERR_error_string(errCode, nil)
	return 0, fmt.Errorf("wolftls: read error: %s (%d)", errMsg, errCode)
}

// Write writes data to the TLS connection. If the handshake has not yet
// completed, it is performed first.
func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.sslWrite == nil {
		return 0, net.ErrClosed
	}
	c.muWrite.Lock()
	defer c.muWrite.Unlock()
	total := 0
	for total < len(b) {
		n := wolfSSL.WolfSSL_write(c.sslWrite, b[total:], uintptr(len(b)-total))
		if n <= 0 {
			errCode := wolfSSL.WolfSSL_get_error(c.sslWrite, n)
			errMsg := wolfSSL.WolfSSL_ERR_error_string(errCode, nil)
			return total, fmt.Errorf("wolftls: write error: %s (%d)", errMsg, errCode)
		}
		total += n
	}
	return total, nil
}

// Close shuts down the TLS connection and closes the underlying transport.
// It is safe to call Close multiple times.
func (c *Conn) Close() error {
	// Kick any in-flight Read/Write goroutines: setting a past deadline
	// on the underlying conn forces the I/O callbacks to return error,
	// which unblocks wolfSSL_read/wolfSSL_write so those goroutines
	// release their RLock and this Close can proceed with Lock. The
	// same kick aborts an in-flight wolfSSL_connect/accept inside
	// doHandshake so we can safely take handshakeMu next.
	if c.conn != nil {
		c.conn.SetDeadline(time.Unix(1, 0))
	}
	// Block until any concurrent doHandshake finishes — otherwise
	// freeSSLLocked below would free c.ssl/c.ctx out from under it
	// (use-after-free in wolfSSL_connect / WolfSSL_get_error).
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.freeSSLLocked()
	runtime.SetFinalizer(c, nil)
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// LocalAddr returns the local network address of the underlying connection.
func (c *Conn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address of the underlying connection.
func (c *Conn) RemoteAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines on the underlying connection.
// wolfSSL will observe these via the file descriptor's socket timeout.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.conn == nil {
		return errors.New("wolftls: connection closed")
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.conn == nil {
		return errors.New("wolftls: connection closed")
	}
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.conn == nil {
		return errors.New("wolftls: connection closed")
	}
	return c.conn.SetWriteDeadline(t)
}

// NetConn returns the underlying net.Conn, or nil if the connection is closed.
func (c *Conn) NetConn() net.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if rc, ok := c.conn.(*recordingConn); ok {
		return rc.Conn
	}
	return c.conn
}

// freeSSL releases the wolfSSL session, CTX, and I/O callback resources.
// Safe for handshake-internal error paths where no concurrent Read/Write
// can be running; for external callers (Close) use freeSSLLocked while
// holding c.mu for writing.
func (c *Conn) freeSSL() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.freeSSLLocked()
}

// freeSSLLocked is the body of freeSSL. c.mu must be held for writing.
func (c *Conn) freeSSLLocked() {
	if c.ssl != nil {
		// Set a short deadline so shutdown doesn't block forever
		// (e.g. if the peer has already closed or we're on net.Pipe).
		if c.conn != nil {
			c.conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		}
		shutdownSSL := c.ssl
		if c.sslWrite != nil {
			shutdownSSL = c.sslWrite
		}
		wolfSSL.WolfSSL_shutdown(shutdownSSL)
		if c.conn != nil {
			c.conn.SetDeadline(time.Time{}) // clear deadline
		}
		if c.sslWrite != nil && c.sslWrite != c.ssl {
			wolfSSL.WolfSSL_free(c.sslWrite)
		}
		c.sslWrite = nil
		wolfSSL.WolfSSL_free(c.ssl)
		c.ssl = nil
	}
	if c.ioConnID != 0 {
		unregisterIOConn(c.ioConnID)
		c.ioConnID = 0
	}
	c.freeCtxLocked()
}

// freeCtxLocked releases just the wolfSSL CTX. c.mu must be held for
// writing if this is called outside handshake-internal paths.
func (c *Conn) freeCtxLocked() {
	if c.certCbID != 0 {
		unregisterCertSetupCallback(c.certCbID)
		c.certCbID = 0
	}
	if c.ctx != nil {
		wolfSSL.WolfSSL_CTX_free(c.ctx)
		c.ctx = nil
	}
}
