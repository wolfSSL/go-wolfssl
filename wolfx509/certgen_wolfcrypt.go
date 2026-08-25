/* certgen_wolfcrypt.go
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

// #cgo CFLAGS: -g -Wall -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
// #include <stdlib.h>
// #include <string.h>
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/asn.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
//
// /* Stub fallbacks so go-wolfssl/wolfx509 builds against a plain
//  * ./configure wolfSSL (no --enable-tailscale, no --enable-certreq, no
//  * -DWOLFSSL_ACME_OID). Cert minting via wolfx509 needs all three to
//  * actually work; without them these wrappers return NOT_COMPILED_IN
//  * (-174) and the caller fails at runtime. The build/link surface
//  * stays clean either way. */
// #ifndef WOLFSSL_CERT_REQ
// static int wc_MakeCertReq(Cert* cert, byte* derBuffer, word32 derSz,
//                            RsaKey* rsaKey, ecc_key* eccKey) {
//     (void)cert; (void)derBuffer; (void)derSz; (void)rsaKey; (void)eccKey;
//     return -174;
// }
// #endif
// #ifndef WOLFSSL_ACME_OID
// static int wc_SetAcmeIdentifierExt(Cert* cert, const byte* keyAuth,
//                                     word32 keyAuthSz) {
//     (void)cert; (void)keyAuth; (void)keyAuthSz;
//     return -174;
// }
// #endif
import "C"
import (
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/wolfssl/go-wolfssl/handles"
)

// TODO: Remove "encoding/asn1" and replace with wolfSSL ASN parsing

// Key usage bits (RFC 5280) in wolfCrypt's KEYUSE_* layout. These are
// the values consumed by wc_MakeCert; translateKeyUsage maps from the
// public wolfx509.KeyUsage constants (which mirror crypto/x509's bit
// ordering) onto these.
const (
	wcKeyUsageDigitalSignature = 0x0080
	wcKeyUsageContentCommit    = 0x0040
	wcKeyUsageKeyEncipherment  = 0x0020
	wcKeyUsageDataEncipherment = 0x0010
	wcKeyUsageKeyAgreement     = 0x0008
	wcKeyUsageCertSign         = 0x0004
	wcKeyUsageCRLSign          = 0x0002
	wcKeyUsageEncipherOnly     = 0x0001
)

// Extended key usage bits in wolfCrypt's EXTKEYUSE_* layout.
const (
	wcExtKeyUsageAny         = 0x01
	wcExtKeyUsageServerAuth  = 0x02
	wcExtKeyUsageClientAuth  = 0x04
	wcExtKeyUsageCodeSigning = 0x08
	wcExtKeyUsageEmailProt   = 0x10
	wcExtKeyUsageTimestamp   = 0x20
	wcExtKeyUsageOCSPSign    = 0x40
)

const (
	asnUTCTimeTag         byte = C.ASN_UTC_TIME
	asnGeneralizedTimeTag byte = C.ASN_GENERALIZED_TIME
)

// sigTypeFor maps a key algorithm to its wolfCrypt CTC_* sigType.
func sigTypeFor(alg handles.Algorithm) (int, error) {
	switch alg {
	case handles.AlgECDSAP256:
		return int(C.CTC_SHA256wECDSA), nil
	default:
		return 0, fmt.Errorf("wolfx509: unsupported key algorithm %d", alg)
	}
}

// certBuildOpts collects the inputs for a single cert or CSR generation.
// All fields are optional unless marked otherwise. NotBefore/NotAfter is
// ignored by CSR generation (CSRs don't carry validity) and required otherwise.
type certBuildOpts struct {
	SubjectCN   string    // CommonName; truncated if >= 64 bytes
	Serial      []byte    // up to 20 bytes; ignored for CSRs, generated if empty
	NotBefore   time.Time // Date marking the start of validity
	NotAfter    time.Time // Date marking the end of validity
	IsCA        bool      // BasicConstraints CA:TRUE
	KeyUsage    int       // OR of wcKeyUsage* constants
	ExtKeyUsage int       // OR of wcExtKeyUsage* constants
	DNSNames    []string  // SubjectAltName dNSName entries
	IPAddresses []net.IP  // SubjectAltName iPAddress entries

	// AcmeKeyAuth, if non-empty, sets the RFC 8737 id-pe-acmeIdentifier
	// (1.3.6.1.5.5.7.1.31) extension on the cert. Pass the raw keyAuth
	// bytes (token "." JWK_thumbprint per RFC 8555 §8.1); wolfCrypt
	// computes the SHA-256 internally. Only honored for certs (not CSRs)
	// and requires wolfSSL built with -DWOLFSSL_ACME_OID.
	AcmeKeyAuth []byte
}

func makeAndSignSelfSignedCert(opts certBuildOpts, key KeyHandle) ([]byte, error) {
	return buildAndSignCert(opts, nil, key, key, false)
}

// makeAndSignCASignedCert signs a cert for leafKey using signerKey (the
// parent's private key) and the parent's issuer name from parentDER.
func makeAndSignCASignedCert(opts certBuildOpts, parentDER []byte, leafKey, signerKey KeyHandle) ([]byte, error) {
	if len(parentDER) == 0 {
		return nil, errors.New("wolfx509: parentDER is required for CA-signed certs")
	}
	return buildAndSignCert(opts, parentDER, leafKey, signerKey, false)
}

// makeAndSignCSR builds a self-signed PKCS#10 CSR. NotBefore / NotAfter /
// IsCA / Serial in opts are ignored.
func makeAndSignCSR(opts certBuildOpts, key KeyHandle) ([]byte, error) {
	return buildAndSignCert(opts, nil, key, key, true)
}

// buildAndSignCert dispatches the C-side cert builder on pubKey.Algorithm().
// parentDER, if non-nil, supplies the issuer name. isCSR routes through
// wc_MakeCertReq (no RNG) instead of wc_MakeCert.
func buildAndSignCert(opts certBuildOpts, parentDER []byte, pubKey, signerKey KeyHandle, isCSR bool) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("wolfx509: pubKey is nil")
	}
	if signerKey == nil {
		return nil, errors.New("wolfx509: signerKey is nil")
	}
	if signerKey.CRngPtr() == nil {
		return nil, errors.New("wolfx509: signerKey has no RNG, and cannot sign")
	}
	if pubKey.Algorithm() != signerKey.Algorithm() {
		return nil, fmt.Errorf("wolfx509: pubKey algorithm %d does not match signerKey algorithm %d",
			pubKey.Algorithm(), signerKey.Algorithm())
	}
	if !isCSR && (opts.NotBefore.IsZero() || opts.NotAfter.IsZero()) {
		return nil, errors.New("wolfx509: NotBefore and NotAfter are required for certs")
	}
	if max := int(C.CTC_SERIAL_SIZE); len(opts.Serial) > max {
		return nil, fmt.Errorf("wolfx509: serial %d bytes > %d max", len(opts.Serial), max)
	}
	if max := int(C.CTC_NAME_SIZE); len(opts.SubjectCN) >= max {
		return nil, fmt.Errorf("wolfx509: SubjectCN %d bytes >= %d max", len(opts.SubjectCN), max)
	}

	sigType, err := sigTypeFor(pubKey.Algorithm())
	if err != nil {
		return nil, err
	}

	var cert C.Cert
	if ret := int(C.wc_InitCert(&cert)); ret != 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_InitCert: %d", ret)
	}
	cert.version = 2
	cert.sigType = C.int(sigType)
	if opts.IsCA {
		cert.isCA = 1
	}
	cert.keyUsage = C.word16(opts.KeyUsage)
	cert.extKeyUsage = C.byte(opts.ExtKeyUsage)

	if !isCSR {
		// NotBefore and NotAfter are set directly rather than relying on
		// daysValid, so explicitly clear this value
		cert.daysValid = 0

		nb := encodeValidityTime(opts.NotBefore)
		na := encodeValidityTime(opts.NotAfter)
		if len(nb) > int(unsafe.Sizeof(cert.beforeDate)) ||
			len(na) > int(unsafe.Sizeof(cert.afterDate)) {
			return nil, fmt.Errorf("wolfx509: encoded validity date exceeds %d-byte cert date buffer", unsafe.Sizeof(cert.beforeDate))
		}
		C.memcpy(unsafe.Pointer(&cert.beforeDate[0]), unsafe.Pointer(&nb[0]), C.size_t(len(nb)))
		cert.beforeDateSz = C.int(len(nb))
		C.memcpy(unsafe.Pointer(&cert.afterDate[0]), unsafe.Pointer(&na[0]), C.size_t(len(na)))
		cert.afterDateSz = C.int(len(na))
	}

	if len(opts.Serial) > 0 && !isCSR {
		C.memcpy(unsafe.Pointer(&cert.serial[0]),
			unsafe.Pointer(&opts.Serial[0]), C.size_t(len(opts.Serial)))
		cert.serialSz = C.int(len(opts.Serial))
	}
	if cn := opts.SubjectCN; cn != "" {
		cnBytes := []byte(cn)
		C.memcpy(unsafe.Pointer(&cert.subject.commonName[0]),
			unsafe.Pointer(&cnBytes[0]), C.size_t(len(cnBytes)))
		cert.subject.commonName[len(cnBytes)] = 0
	}

	if len(opts.DNSNames) > 0 || len(opts.IPAddresses) > 0 {
		sans, err := buildSANsDER(opts.DNSNames, opts.IPAddresses)
		if err != nil {
			return nil, fmt.Errorf("wolfx509: build SANs: %w", err)
		}
		if len(sans) > int(unsafe.Sizeof(cert.altNames)) {
			return nil, fmt.Errorf("wolfx509: SAN blob %d bytes exceeds cert.altNames size", len(sans))
		}
		C.memcpy(unsafe.Pointer(&cert.altNames[0]),
			unsafe.Pointer(&sans[0]), C.size_t(len(sans)))
		cert.altNamesSz = C.int(len(sans))
	}

	if len(parentDER) > 0 {
		if ret := int(C.wc_SetIssuerBuffer(&cert,
			(*C.byte)(unsafe.Pointer(&parentDER[0])), C.int(len(parentDER)))); ret != 0 {
			return nil, fmt.Errorf("wolfCrypt: wc_SetIssuerBuffer: %d", ret)
		}
	}

	if !isCSR && len(opts.AcmeKeyAuth) > 0 {
		if ret := int(C.wc_SetAcmeIdentifierExt(&cert,
			(*C.byte)(unsafe.Pointer(&opts.AcmeKeyAuth[0])),
			C.word32(len(opts.AcmeKeyAuth)))); ret != 0 {
			return nil, fmt.Errorf("wolfCrypt: wc_SetAcmeIdentifierExt: %d", ret)
		}
	}

	derOut := make([]byte, 4096)
	derPtr := (*C.byte)(unsafe.Pointer(&derOut[0]))
	derCap := C.word32(len(derOut))

	var bodySz, signedSz int
	switch pubKey.Algorithm() {
	case handles.AlgECDSAP256:
		pubEcc := (*C.ecc_key)(pubKey.CKeyPtr())
		signerEcc := (*C.ecc_key)(signerKey.CKeyPtr())
		signerRng := (*C.WC_RNG)(signerKey.CRngPtr())
		if isCSR {
			bodySz = int(C.wc_MakeCertReq(&cert, derPtr, derCap, nil, pubEcc))
		} else {
			bodySz = int(C.wc_MakeCert(&cert, derPtr, derCap, nil, pubEcc, signerRng))
		}
		if bodySz < 0 {
			return nil, fmt.Errorf("wolfCrypt: body build failed: %d", bodySz)
		}
		signedSz = int(C.wc_SignCert(cert.bodySz, cert.sigType, derPtr, derCap,
			nil, signerEcc, signerRng))
	default:
		return nil, fmt.Errorf("wolfx509: cert builder for algorithm %d not implemented",
			pubKey.Algorithm())
	}
	if signedSz < 0 {
		return nil, fmt.Errorf("wolfCrypt: wc_SignCert: %d", signedSz)
	}
	return derOut[:signedSz], nil
}

// buildSANsDER serializes dnsNames + ipAddresses as an ASN.1 SEQUENCE of
// GeneralName CHOICE elements (RFC 5280 §4.2.1.6). Context-specific
// implicit tags: dNSName=[2] IA5String, iPAddress=[7] OCTET STRING.
func buildSANsDER(dnsNames []string, ipAddresses []net.IP) ([]byte, error) {
	var entries []asn1.RawValue
	for _, name := range dnsNames {
		entries = append(entries, asn1.RawValue{
			Tag: 2, Class: asn1.ClassContextSpecific, IsCompound: false,
			Bytes: []byte(name),
		})
	}
	for _, ip := range ipAddresses {
		b := ip.To4()
		if b == nil {
			b = ip.To16()
		}
		if b == nil {
			return nil, fmt.Errorf("invalid IP %v", ip)
		}
		entries = append(entries, asn1.RawValue{
			Tag: 7, Class: asn1.ClassContextSpecific, IsCompound: false,
			Bytes: b,
		})
	}
	return asn1.Marshal(entries)
}
