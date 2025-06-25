/* certVerify.go
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

package main

import (
	"fmt"
	"os"

    	wolfSSL "github.com/wolfssl/go-wolfssl"
)

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", path, err)
	}
	return data, nil
}

func loadX509(certData []byte) *wolfSSL.WOLFSSL_X509 {
	ret := wolfSSL.WolfSSL_X509_load_certificate_buffer(certData, len(certData), wolfSSL.SSL_FILETYPE_PEM)
	return ret
}

func main() {
	caPath   := "../certs/ca-cert.pem"
	int1Path := "../certs/ca-int-cert.pem"
	int2Path := "../certs/ca-int2-cert.pem"
	leafPath := "../certs/client-int-cert.pem"


	int1Cert, err := readFile(int1Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	int2Cert, err := readFile(int2Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	leafCert, err := readFile(leafPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Convert to internal WOLFSSL_X509
	x509Int1 := loadX509(int1Cert)
	x509Int2 := loadX509(int2Cert)
	x509Leaf := loadX509(leafCert)
	if x509Int1 == nil || x509Int2 == nil || x509Leaf == nil {
		fmt.Fprintln(os.Stderr, "Error converting one or more certificates to wolfSSL X509")
		os.Exit(1)
	}

	// Create store and load CA file
	store := wolfSSL.WolfSSL_X509_STORE_new()
	if store == nil {
		fmt.Fprintln(os.Stderr, "Failed to create X509 store")
		os.Exit(1)
	}
	defer wolfSSL.WolfSSL_X509_STORE_free(store)

	if ret := wolfSSL.WolfSSL_X509_STORE_load_file(store, caPath); ret != 1 {
		fmt.Fprintln(os.Stderr, "Failed to load CA cert into store")
		os.Exit(1)
	}

	// Create stack for intermediates
	inter := wolfSSL.WolfSSL_sk_X509_new_null()
	if inter == nil {
		fmt.Fprintln(os.Stderr, "Failed to create intermediate cert stack")
		os.Exit(1)
	}
	defer wolfSSL.WolfSSL_sk_X509_free(inter)

	wolfSSL.WolfSSL_sk_X509_push(inter, x509Int1)
	wolfSSL.WolfSSL_sk_X509_push(inter, x509Int2)

	// Setup store context
	ctx := wolfSSL.WolfSSL_X509_STORE_CTX_new()
	if ctx == nil {
		fmt.Fprintln(os.Stderr, "Failed to create X509_STORE_CTX")
		os.Exit(1)
	}
	defer wolfSSL.WolfSSL_X509_STORE_CTX_free(ctx)

	if ret := wolfSSL.WolfSSL_X509_STORE_CTX_init(ctx, store, x509Leaf, inter); ret != 1 {
		fmt.Fprintln(os.Stderr, "X509_STORE_CTX_init failed")
		os.Exit(1)
	}

	// Perform verification
	if ret := wolfSSL.WolfSSL_X509_verify_cert(ctx); ret != 1 {
		fmt.Fprintln(os.Stderr, "Certificate verification FAILED")
		os.Exit(1)
	}

	fmt.Println("Certificate chain verified successfully.")
}

