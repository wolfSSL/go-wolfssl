/* name.go
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
	"strings"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// Name is a minimal stand-in for crypto/x509's pkix.Name. Only the fields
// that Tailscale actually reads are populated.
type Name struct {
	// CommonName is the CN RDN, extracted via
	// wolfSSL_X509_NAME_get_text_by_NID(NID_commonName).
	CommonName string

	// oneline is the DN formatted by wolfSSL_X509_NAME_oneline in OpenSSL's
	// "/C=US/O=..." form. Used for blockblame's Issuer.String() matching.
	oneline string
}

// String returns the one-line DN (RFC 2253-ish, the OpenSSL format).
func (n Name) String() string { return n.oneline }

// nameFromWolfSSL extracts a Name from a *WOLFSSL_X509_NAME. The returned
// Name is pure Go memory; the underlying X509_NAME pointer is owned by the
// parent certificate and not retained here.
func nameFromWolfSSL(raw *wolfSSL.WOLFSSL_X509_NAME) Name {
	if raw == nil {
		return Name{}
	}
	oneline := wolfSSL.WolfSSL_X509_NAME_oneline(raw)
	cn := wolfSSL.WolfSSL_X509_NAME_get_text_by_NID(raw, wolfSSL.NID_commonName)
	if cn == "" {
		// NAME_get_text_by_NID isn't reliably exported for all DN fields
		// in the OpenSSL-extra subset (hit during CA-signed leaf issuer
		// parsing). Fall back to parsing "/CN=..." out of the oneline.
		cn = extractCNFromOneline(oneline)
	}
	return Name{CommonName: cn, oneline: oneline}
}

// extractCNFromOneline parses a /CN=... RDN out of an OpenSSL-style
// "/C=.../O=.../CN=..." oneline string. Returns "" if no CN is found.
func extractCNFromOneline(oneline string) string {
	const tag = "/CN="
	i := strings.Index(oneline, tag)
	if i < 0 {
		return ""
	}
	rest := oneline[i+len(tag):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// equalName reports whether two Names have the same oneline representation.
func equalName(a, b Name) bool {
	return a.oneline == b.oneline
}

// equalRaw reports whether two raw byte slices are equal, used for
// RawSubject/RawIssuer comparison.
func equalRaw(a, b []byte) bool { return bytes.Equal(a, b) }
