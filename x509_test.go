/* x509_test.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package wolfSSL

import (
	"testing"
)

// BIO must accept a Go slice (wrapper copies to C heap) without cgo violation.
func TestBIO_NewMemBuf_NoCgoViolation(t *testing.T) {
	buf := []byte("dummy buffer content for BIO test")
	bio := WolfSSL_BIO_new_mem_buf(buf, len(buf))
	if bio == nil {
		t.Skip("BIO_new_mem_buf returned NULL (likely build without BIO support)")
	}
	if ret := WolfSSL_BIO_free(bio); ret < 0 {
		t.Fatalf("BIO_free returned %d", ret)
	}
}

// Free-on-nil must be a no-op (matches OpenSSL/wolfSSL convention).
func TestBIO_FreeNil_DoesNotCrash(t *testing.T) {
	WolfSSL_BIO_free(nil)
}

// ASN1_get_object on a Go slice must not trigger cgo's pointer-rule violation.
func TestASN1_GetObject_NoCgoViolation(t *testing.T) {
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	in := der
	var objLen, tag, cls int
	WolfSSL_ASN1_get_object(&in, &objLen, &tag, &cls, len(der))
}

// Pre-cgo bounds check: empty / oversized / negative inLen must not panic.
func TestASN1_GetObject_BoundaryInputs_NoPanic(t *testing.T) {
	cases := []struct {
		name  string
		in    []byte
		inLen int
	}{
		{"empty", []byte{}, 0},
		{"oversized inLen", []byte{0x30, 0x00}, 1 << 20},
		{"negative inLen", []byte{0x30, 0x00}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %q panicked: %v", tc.name, r)
				}
			}()
			in := tc.in
			var objLen, tag, cls int
			WolfSSL_ASN1_get_object(&in, &objLen, &tag, &cls, tc.inLen)
		})
	}
}

// d2i_ASN1_OBJECT with empty / oversized inputs.
func TestD2I_ASN1_OBJECT_BoundaryInputs_NoPanic(t *testing.T) {
	cases := []struct {
		name   string
		der    []byte
		length int
	}{
		{"empty", []byte{}, 0},
		{"oversized length", []byte{0x06, 0x01, 0x01}, 1 << 20},
		{"negative length", []byte{0x06, 0x01, 0x01}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %q panicked: %v", tc.name, r)
				}
			}()
			der := tc.der
			WolfSSL_d2i_ASN1_OBJECT(nil, &der, tc.length)
		})
	}
}

// X509_load_certificate_buffer with invalid inputs must error/return nil, not panic.
func TestX509_LoadCertBuffer_InvalidInputs_NoPanic(t *testing.T) {
	cases := []struct {
		name   string
		buff   []byte
		buffSz int
	}{
		{"empty buffer", []byte{}, 0},
		{"oversized buffSz", []byte{0x01}, 1 << 20},
		{"negative buffSz", []byte{0x01}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %q panicked: %v", tc.name, r)
				}
			}()
			if got := WolfSSL_X509_load_certificate_buffer(tc.buff, tc.buffSz, SSL_FILETYPE_PEM); got != nil {
				WolfSSL_X509_free(got)
				t.Fatalf("expected nil for invalid input, got non-nil")
			}
		})
	}
}
