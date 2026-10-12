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

// #include <stdlib.h>
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
//
// /* Before 5.9.2 an IP check also fell back to the subject CN. */
// static int wolftls_check_ip_address(WOLFSSL* ssl, const char* ip) {
// #if !defined(WOLFSSL_IP_ALT_NAME)
//     (void)ssl; (void)ip;
//     return -2;
// #elif LIBWOLFSSL_VERSION_HEX >= 0x05009002 || \
//     (LIBWOLFSSL_VERSION_HEX >= 0x05009001 && \
//      defined(WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY))
//     return wolfSSL_check_ip_address(ssl, ip);
// #elif defined(OPENSSL_EXTRA) && defined(WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY)
//     return wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(wolfSSL_get0_param(ssl), ip);
// #else
//     (void)ssl; (void)ip;
//     return -1;
// #endif
// }
//
// static int wolftls_set_default_min_version(WOLFSSL_CTX* ctx) {
// #ifdef WOLFSSL_SYS_CRYPTO_POLICY
//     if (wolfSSL_crypto_policy_is_enabled())
//         return WOLFSSL_SUCCESS;
// #endif
// #if !defined(WOLFSSL_NO_TLS12)
//     return wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
// #elif defined(WOLFSSL_TLS13)
//     return wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
// #else
//     (void)ctx;
//     return WOLFSSL_FAILURE;
// #endif
// }
import "C"

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

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

	// CertDER is the DER-encoded certificate chain (alternative to PEM):
	// CertDER[0] is the leaf, followed by intermediates in sending order.
	CertDER [][]byte

	// KeyDER is the DER-encoded private key (alternative to PEM).
	KeyDER []byte
}

// Config structures a TLS connection's parameters.
type Config struct {
	// ServerName is the value sent in the SNI extension and, for clients, is
	// used for hostname verification. An IP literal (optionally bracketed,
	// IPv6 may carry a zone) is not sent in SNI and is verified against the
	// certificate's IP SANs instead. A client that verifies the peer
	// (InsecureSkipVerify == false) must set ServerName: otherwise the
	// certificate name is never checked, so doHandshake rejects the connection
	// before the handshake, matching crypto/tls. Set InsecureSkipVerify to
	// connect without a ServerName.
	ServerName string

	// InsecureSkipVerify disables wolfSSL's built-in certificate verification.
	// It is also the alternative to setting ServerName: when false, a client
	// must provide ServerName so the certificate name can be checked. When
	// true, the VerifyConnection callback (if set) is still called after the
	// handshake so the caller can perform custom verification.
	//
	// This determines how a client verifies the server, setting it on a
	// server is a no-op.
	InsecureSkipVerify bool

	// RootCAPEMs provides root CA certificates as raw PEM blocks for direct
	// loading into wolfSSL's certificate store.
	RootCAPEMs [][]byte

	// Certificates supplies the certificate chain to present to the other
	// side of the connection. Servers must include at least
	// one certificate unless GetCertificate is set.
	//
	// Only Certificates[0] is used. Unlike crypto/tls, a WOLFSSL_CTX has a
	// single certificate/private-key slot, and loading a second chain would
	// replace the first.
	//
	// TODO: Implement support for multiple certs/identities to match crypto/tls
	Certificates []Certificate

	// GetCertificate returns a certificate based on the ClientHello. It is
	// called on every server handshake (wolfSSL must be built with
	// WOLFSSL_CERT_SETUP_CB); ServerName is empty when the client sent no
	// SNI. A returned certificate overrides Certificates. Returning nil, nil
	// falls back to Certificates[0], or fails the handshake when Certificates
	// is empty. A returned error aborts the handshake.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// NextProtos is a list of supported application-level protocols for ALPN
	// negotiation, in order of preference. Each entry must be 1-255 bytes
	// and must not contain ',' or NUL, or the handshake is rejected.
	NextProtos []string

	// MinVersion is the minimum TLS version to accept.
	// Zero means TLS 1.2, matching crypto/tls, unless a system crypto
	// policy owns the floor.
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
	// list is used. Each element is a wolfSSL cipher suite name string; an
	// empty element or one containing NUL rejects the handshake.
	CipherSuites []string

	// ClientAuth controls how the server handles client certificates.
	// Ignored on the client side. NoClientCert (the zero value) requests
	// no client certificate at all, and one sent anyway is not verified.
	// Every other value requests a certificate and, unlike crypto/tls,
	// verifies any certificate the client presents against RootCAPEMs, so
	// RequestClientCert behaves as VerifyClientCertIfGiven and
	// RequireAnyClientCert as RequireAndVerifyClientCert. The two Require
	// values also fail the handshake when the client sends no certificate.
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

// setDefaultMinVersion sets the TLS 1.2 floor used when MinVersion is zero.
// It uses the native setter, which builds without OPENSSL_EXTRA also have.
func setDefaultMinVersion(ctx *wolfSSL.WOLFSSL_CTX) int {
	return int(C.wolftls_set_default_min_version((*C.WOLFSSL_CTX)(unsafe.Pointer(ctx))))
}

// serverNameIP returns the address when ServerName is an IP literal
// (optionally bracketed, IPv6 may carry a zone), or nil for a host name.
func serverNameIP(name string) net.IP {
	if len(name) >= 2 && name[0] == '[' && name[len(name)-1] == ']' {
		name = name[1 : len(name)-1]
	}
	zone := ""
	if i := strings.IndexByte(name, '%'); i >= 0 {
		name, zone = name[:i], name[i+1:]
		if zone == "" {
			return nil
		}
	}
	ip := net.ParseIP(name)
	if ip == nil || (zone != "" && strings.IndexByte(name, ':') < 0) {
		return nil
	}
	return ip
}

// ipCheckUnavailable is returned by sslCheckIPAddress when the wolfSSL build
// has no IP check that ignores the subject CN.
const ipCheckUnavailable = -1

// ipAltNameMissing is returned by sslCheckIPAddress when wolfSSL does not
// decode IP SANs (built without WOLFSSL_IP_ALT_NAME).
const ipAltNameMissing = -2

// sslCheckIPAddress makes wolfSSL match the peer leaf's IP SANs against ip.
// wolfSSL renders IPv6 SANs as eight uppercase four-digit groups.
func sslCheckIPAddress(ssl *wolfSSL.WOLFSSL, ip net.IP) int {
	asc := ip.String()
	if v4 := ip.To4(); v4 == nil {
		var b strings.Builder
		for i := 0; i < net.IPv6len; i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			fmt.Fprintf(&b, "%02X%02X", ip[i], ip[i+1])
		}
		asc = b.String()
	}
	cs := C.CString(asc)
	defer C.free(unsafe.Pointer(cs))
	return int(C.wolftls_check_ip_address((*C.WOLFSSL)(unsafe.Pointer(ssl)), cs))
}

// checkNextProtos rejects ALPN names that cannot be passed through
// wolfSSL_UseALPN's comma-separated C string unchanged.
func checkNextProtos(protos []string) error {
	for _, p := range protos {
		if len(p) == 0 || len(p) > 255 {
			return fmt.Errorf("wolftls: invalid NextProtos entry length %d", len(p))
		}
		if strings.ContainsAny(p, ",\x00") {
			return fmt.Errorf("wolftls: NextProtos entry %q contains ',' or NUL", p)
		}
	}
	return nil
}

// checkCipherSuites rejects entries a C string would truncate or that are
// empty; ':' is kept so pre-joined wolfSSL cipher lists still work.
func checkCipherSuites(suites []string) error {
	for _, cs := range suites {
		if cs == "" || strings.IndexByte(cs, 0) >= 0 {
			return fmt.Errorf("wolftls: invalid CipherSuites entry %q", cs)
		}
	}
	return nil
}

// derChain concatenates CertDER in order so the leaf and its intermediates
// load through wolfSSL's chain API. It returns nil, which wolfSSL rejects,
// when any entry is empty, so a later certificate never becomes the leaf.
func (cert *Certificate) derChain() []byte {
	var out []byte
	for _, der := range cert.CertDER {
		if len(der) == 0 {
			return nil
		}
		out = append(out, der...)
	}
	return out
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
