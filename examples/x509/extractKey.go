/* extractKey.go
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
	leafPath := "../certs/server-ecc.pem"


	leafCert, err := readFile(leafPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Convert to internal WOLFSSL_X509
	x509Leaf := loadX509(leafCert)
	if x509Leaf == nil {
		fmt.Fprintln(os.Stderr, "Error converting one or more certificates to wolfSSL X509")
		os.Exit(1)
	}

	// First call to get required buffer size
	var pubLen int
	ret := wolfSSL.WolfSSL_X509_get_pubkey_buffer(x509Leaf, nil, &pubLen)
	if ret != 1 || pubLen <= 0 {
		fmt.Fprintln(os.Stderr, "Failed to determine public key buffer size")
		os.Exit(1)
	}

	// Allocate buffer and extract public key
	pubBuf := make([]byte, pubLen)
	ret = wolfSSL.WolfSSL_X509_get_pubkey_buffer(x509Leaf, pubBuf, &pubLen)
	if ret != 1 {
		fmt.Fprintln(os.Stderr, "Failed to extract public key from leaf certificate")
		os.Exit(1)
	}

	fmt.Printf("Extracted leaf cert public key DER (%d bytes):\n", pubLen)
	fmt.Printf("%x\n", pubBuf)

	digest := make([]byte, wolfSSL.WC_SHA384_DIGEST_SIZE )
        wolfSSL.Wc_Sha384Hash(pubBuf, pubLen, digest)
	fmt.Printf("SHA484 hash of public key DER\n")
	fmt.Printf("%x\n", digest)

	var pubKey wolfSSL.Ecc_key
	if ret = wolfSSL.Wc_ecc_init(&pubKey); ret != 0 {
		fmt.Fprintln(os.Stderr, "Failed to initialize ECC key")
		os.Exit(1)
        }

	idx := 0
	if ret = wolfSSL.Wc_EccPublicKeyDecode(pubBuf, &idx, &pubKey, pubLen); ret != 0 {
		print("Return is ",ret)
		fmt.Fprintln(os.Stderr, "Failed to import DER buffer into ECC key")
		os.Exit(1)
        }
	
	fmt.Println("Successfully imported ECC public key structure from DER buffer")
        
	wolfSSL.Wc_ecc_free(&pubKey)
}

