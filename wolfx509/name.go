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
	"encoding/asn1"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

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
	return Name{CommonName: cn, oneline: oneline}
}

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// issuerCommonName returns the first CN attribute of the issuer Name in a
// DER certificate, or "" if there is none or the DER cannot be walked.
func issuerCommonName(der []byte) string {
	var cert, tbs, field asn1.RawValue
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return ""
	}
	if _, err := asn1.Unmarshal(cert.Bytes, &tbs); err != nil {
		return ""
	}
	rest, err := asn1.Unmarshal(tbs.Bytes, &field)
	if err == nil && field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
		rest, err = asn1.Unmarshal(rest, &field) // explicit version precedes serial
	}
	for i := 0; i < 2 && err == nil; i++ { // signature, issuer
		rest, err = asn1.Unmarshal(rest, &field)
	}
	if err != nil {
		return ""
	}
	var rdns []asn1.RawValue
	if _, err := asn1.Unmarshal(field.FullBytes, &rdns); err != nil {
		return ""
	}
	for _, rdn := range rdns {
		var atvs []struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.UnmarshalWithParams(rdn.FullBytes, &atvs, "set"); err != nil {
			return ""
		}
		for _, atv := range atvs {
			if atv.Type.Equal(oidCommonName) {
				return directoryString(atv.Value)
			}
		}
	}
	return ""
}

// directoryString decodes the DirectoryString forms seen in CN attributes.
func directoryString(v asn1.RawValue) string {
	switch v.Tag {
	case asn1.TagUTF8String:
		if !utf8.Valid(v.Bytes) {
			return ""
		}
		return string(v.Bytes)
	case asn1.TagPrintableString, asn1.TagIA5String:
		for _, b := range v.Bytes {
			if b >= utf8.RuneSelf {
				return ""
			}
		}
		return string(v.Bytes)
	case asn1.TagT61String:
		// Decoded as Latin-1, as crypto/x509 does.
		r := make([]rune, len(v.Bytes))
		for i, b := range v.Bytes {
			r[i] = rune(b)
		}
		return string(r)
	case asn1.TagBMPString:
		if len(v.Bytes)%2 != 0 {
			return ""
		}
		r := make([]rune, len(v.Bytes)/2)
		for i := range r {
			c := rune(v.Bytes[2*i])<<8 | rune(v.Bytes[2*i+1])
			if utf16.IsSurrogate(c) {
				return ""
			}
			r[i] = c
		}
		return string(r)
	case tagUniversalString:
		if len(v.Bytes)%4 != 0 {
			return ""
		}
		r := make([]rune, len(v.Bytes)/4)
		for i := range r {
			c := uint32(v.Bytes[4*i])<<24 | uint32(v.Bytes[4*i+1])<<16 | uint32(v.Bytes[4*i+2])<<8 | uint32(v.Bytes[4*i+3])
			if c > unicode.MaxRune || (c >= 0xd800 && c <= 0xdfff) {
				return ""
			}
			r[i] = rune(c)
		}
		return string(r)
	}
	return ""
}

// tagUniversalString is the ASN.1 UniversalString tag, which encoding/asn1
// has no constant for.
const tagUniversalString = 28

// equalName reports whether two Names have the same oneline representation.
func equalName(a, b Name) bool {
	return a.oneline == b.oneline
}

// equalRaw reports whether two raw byte slices are equal, used for
// RawSubject/RawIssuer comparison.
func equalRaw(a, b []byte) bool { return bytes.Equal(a, b) }
