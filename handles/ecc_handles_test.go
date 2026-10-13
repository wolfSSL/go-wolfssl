/* ecc_handles_test.go
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

package handles

import (
	"bytes"
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

func TestEccKeyMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		marshal func(*EccKey) ([]byte, error)
		parse   func([]byte) (*EccKey, error)
	}{
		{"SEC1DER", MarshalSEC1DER, ParseECPrivateKeyDER},
		{"SEC1PEM", MarshalSEC1PEM, ParseECPrivateKeyPEM},
		{"PKCS8DER", MarshalPKCS8DER, ParsePKCS8ECPrivateKeyDER},
		{"PKCS8PEM", MarshalPKCS8PEM, ParseECPrivateKeyPEM},
	}

	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := tc.marshal(k)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			k2, err := tc.parse(enc)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer k2.Free()
			enc2, err := tc.marshal(k2)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if !bytes.Equal(enc, enc2) {
				t.Fatalf("round trip mismatch:\n got %x\nwant %x", enc2, enc)
			}
		})
	}
}

func TestEccPrivateKeyToDer(t *testing.T) {
	k, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}
	defer k.Free()

	buf := make([]byte, 256)
	n := wolfSSL.Wc_EccPrivateKeyToDer(k.Raw(), buf)
	if n <= 0 {
		t.Fatalf("Wc_EccPrivateKeyToDer: %d", n)
	}
	enc := buf[:n]
	k2, err := ParseECPrivateKeyDER(enc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer k2.Free()

	buf2 := make([]byte, 256)
	n2 := wolfSSL.Wc_EccPrivateKeyToDer(k2.Raw(), buf2)
	if n2 <= 0 {
		t.Fatalf("Re - Wc_EccPrivateKeyToDer: %d", n2)
	}
	if enc2 := buf2[:n2]; !bytes.Equal(enc, enc2) {
		t.Fatalf("round trip mismatch:\n got %x\nwant %x", enc2, enc)
	}
}
