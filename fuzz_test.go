/* fuzz_test.go
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

package wolfSSL

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// fuzzSeedCertsDER returns the DER of every certificate in examples/certs.
func fuzzSeedCertsDER(f *testing.F) [][]byte {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("examples", "certs", "*.pem"))
	if err != nil {
		f.Fatal(err)
	}
	var ders [][]byte
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
			if block.Type == "CERTIFICATE" {
				ders = append(ders, block.Bytes)
			}
		}
	}
	return ders
}

func FuzzX509DER(f *testing.F) {
	for _, der := range fuzzSeedCertsDER(f) {
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		if x := WolfSSL_d2i_X509(der); x != nil {
			WolfSSL_X509_free(x)
		}
		if x := WolfSSL_X509_load_certificate_buffer(der, len(der), SSL_FILETYPE_ASN1); x != nil {
			WolfSSL_X509_free(x)
		}
	})
}

func FuzzX509PEM(f *testing.F) {
	for _, der := range fuzzSeedCertsDER(f) {
		f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		if x := WolfSSL_X509_load_certificate_buffer(p, len(p), SSL_FILETYPE_PEM); x != nil {
			WolfSSL_X509_free(x)
		}
	})
}

func FuzzRsaPrivateKeyDecode(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(x509.MarshalPKCS1PrivateKey(key))
	f.Fuzz(func(t *testing.T, der []byte) {
		var k RsaKey
		if Wc_InitRsaKey(&k) != 0 {
			t.Skip("RSA unavailable in this build")
		}
		defer Wc_FreeRsaKey(&k)
		Wc_RsaPrivateKeyDecode(der, &k)
	})
}
