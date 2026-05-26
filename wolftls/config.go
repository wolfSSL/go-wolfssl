/* config.go
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

// TLS version constants, matching crypto/tls values.
const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// ClientAuthType mirrors crypto/tls.ClientAuthType. Values match so a
// stdlib tls.Config.ClientAuth can be assigned directly.
type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// ClientHelloInfo contains information from a ClientHello message in order
// to guide certificate selection in the GetCertificate callback.
type ClientHelloInfo struct {
	ServerName string

	// SupportedProtos is the list of ALPN protocols the client offered
	// in the ClientHello, in client preference order. Empty if the
	// peer didn't send an ALPN extension. Populated by wolftls before
	// invoking the GetCertificate callback so callers (e.g.,
	// autocert.Manager) can detect TLS-ALPN-01 challenge handshakes.
	SupportedProtos []string
}

// Certificate holds a certificate chain and its associated private key,
// stored as raw DER and PEM bytes for loading into wolfSSL.
type Certificate struct {
	// CertPEM is the PEM-encoded certificate chain. May contain
	// multiple certificates concatenated.
	CertPEM []byte

	// KeyPEM is the PEM-encoded private key.
	KeyPEM []byte

	// CertDER is the DER-encoded certificate (alternative to PEM).
	CertDER [][]byte

	// KeyDER is the DER-encoded private key (alternative to PEM).
	KeyDER []byte
}

// Config structures a TLS connection's parameters.
type Config struct {
	// ServerName is the value sent in the SNI extension. For clients,
	// it is also used for hostname verification unless InsecureSkipVerify is set.
	ServerName string

	// InsecureSkipVerify disables wolfSSL's built-in certificate verification.
	// When true, the VerifyConnection callback (if set) is still called after
	// the handshake so the caller can perform custom verification.
	InsecureSkipVerify bool

	// RootCAPEMs provides root CA certificates as raw PEM blocks for direct
	// loading into wolfSSL's certificate store.
	RootCAPEMs [][]byte

	// Certificates contains one or more certificate chains to present to
	// the other side of the connection. Server configurations must include
	// at least one certificate unless GetCertificate is set.
	Certificates []Certificate

	// GetCertificate returns a certificate based on the ClientHello. It is
	// called on the server side when an SNI extension is received. If set
	// and the callback returns a certificate, it overrides Certificates.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// NextProtos is a list of supported application-level protocols for ALPN
	// negotiation, in order of preference.
	NextProtos []string

	// MinVersion is the minimum TLS version to accept.
	// Zero means no minimum (wolfSSL default, typically TLS 1.2).
	MinVersion uint16

	// MaxVersion is the maximum TLS version to accept.
	// Zero means no maximum (wolfSSL default, typically TLS 1.3).
	MaxVersion uint16

	// VerifyConnection is called after a successful handshake. If it returns
	// an error, the handshake is aborted and that error is returned.
	// The ConnectionState will have PeerCertificates populated.
	VerifyConnection func(ConnectionState) error

	// VerifyPeerCertificate is called after normal certificate verification
	// (or after skipping it if InsecureSkipVerify is true). rawCerts contains
	// the DER-encoded peer certificate chain.
	VerifyPeerCertificate func(rawCerts [][]byte) error

	// CipherSuites is the list of enabled cipher suites. If nil, a default
	// list is used. Each element is a wolfSSL cipher suite name string.
	CipherSuites []string

	// ClientAuth controls how the server handles client certificates.
	// Ignored on the client side. When set to RequireAnyClientCert or
	// RequireAndVerifyClientCert, the server will fail the handshake if
	// the client does not present a certificate. When set to
	// VerifyClientCertIfGiven or RequireAndVerifyClientCert, wolfSSL
	// verifies the presented client cert against the pool loaded via
	// RootCAPEMs (wolfSSL uses the same verify store for peer certs
	// regardless of client/server role).
	ClientAuth ClientAuthType
}

// Clone returns a deep copy of c. Slices are copied so the caller can
// modify the clone without affecting the original.
func (c *Config) Clone() *Config {
	if c == nil {
		return &Config{}
	}
	clone := *c

	if c.RootCAPEMs != nil {
		clone.RootCAPEMs = make([][]byte, len(c.RootCAPEMs))
		for i, pem := range c.RootCAPEMs {
			clone.RootCAPEMs[i] = append([]byte(nil), pem...)
		}
	}
	if c.Certificates != nil {
		clone.Certificates = make([]Certificate, len(c.Certificates))
		for i, cert := range c.Certificates {
			clone.Certificates[i] = cert.clone()
		}
	}
	if c.NextProtos != nil {
		clone.NextProtos = make([]string, len(c.NextProtos))
		copy(clone.NextProtos, c.NextProtos)
	}
	if c.CipherSuites != nil {
		clone.CipherSuites = make([]string, len(c.CipherSuites))
		copy(clone.CipherSuites, c.CipherSuites)
	}

	return &clone
}

func (cert Certificate) clone() Certificate {
	c := cert
	if cert.CertPEM != nil {
		c.CertPEM = append([]byte(nil), cert.CertPEM...)
	}
	if cert.KeyPEM != nil {
		c.KeyPEM = append([]byte(nil), cert.KeyPEM...)
	}
	if cert.CertDER != nil {
		c.CertDER = make([][]byte, len(cert.CertDER))
		for i, der := range cert.CertDER {
			c.CertDER[i] = append([]byte(nil), der...)
		}
	}
	if cert.KeyDER != nil {
		c.KeyDER = append([]byte(nil), cert.KeyDER...)
	}
	return c
}
