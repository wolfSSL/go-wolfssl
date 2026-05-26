/* state.go
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

// ConnectionState contains information about the state of a TLS connection
// after the handshake has completed. It mirrors the most commonly used
// fields from crypto/tls.ConnectionState.
type ConnectionState struct {
	// Version is the negotiated TLS version (e.g. VersionTLS12, VersionTLS13).
	Version uint16

	// HandshakeComplete is true if the TLS handshake has completed.
	HandshakeComplete bool

	// CipherSuite is the cipher suite negotiated for the connection,
	// represented as a wolfSSL cipher suite name string.
	CipherSuite string

	// NegotiatedProtocol is the application protocol negotiated via ALPN.
	NegotiatedProtocol string

	// ServerName is the SNI value sent by the client.
	ServerName string

	// PeerCertificates are the DER-encoded certificates sent by the peer,
	// in the order sent. The first element is the leaf certificate.
	PeerCertificates [][]byte
}

// parseVersion converts a wolfSSL version string (e.g., "TLSv1.2", "TLSv1.3")
// to the standard TLS version constant.
func parseVersion(v string) uint16 {
	switch v {
	case "TLSv1":
		return VersionTLS10
	case "TLSv1.1":
		return VersionTLS11
	case "TLSv1.2":
		return VersionTLS12
	case "TLSv1.3":
		return VersionTLS13
	default:
		return 0
	}
}
