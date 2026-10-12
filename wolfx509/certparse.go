/* certparse.go
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

// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
// #include <wolfssl/openssl/x509v3.h>
//
// #ifdef OPENSSL_EXTRA
// static int wolfx509_basic_constraints(WOLFSSL_X509* x, int* isCA) {
//     *isCA = wolfSSL_X509_get_isCA(x);
//     return wolfSSL_X509_ext_isSet_by_NID(x, WC_NID_basic_constraints);
// }
// static int wolfx509_key_usage(WOLFSSL_X509* x, unsigned int* usage) {
//     *usage = wolfSSL_X509_get_keyUsage(x);
//     return wolfSSL_X509_ext_isSet_by_NID(x, WC_NID_key_usage);
// }
// #else
// static int wolfx509_basic_constraints(WOLFSSL_X509* x, int* isCA) {
//     (void)x; *isCA = 0; return 0;
// }
// static int wolfx509_key_usage(WOLFSSL_X509* x, unsigned int* usage) {
//     (void)x; *usage = 0; return 0;
// }
// #endif
import "C"
import (
	"encoding/asn1"
	"fmt"
	"net"
	"unsafe"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// extKeyUsageOIDs mirrors crypto/x509's ExtKeyUsage OID table.
var extKeyUsageOIDs = []struct {
	oid asn1.ObjectIdentifier
	eku ExtKeyUsage
}{
	{asn1.ObjectIdentifier{2, 5, 29, 37, 0}, ExtKeyUsageAny},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, ExtKeyUsageServerAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, ExtKeyUsageClientAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, ExtKeyUsageCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, ExtKeyUsageEmailProtection},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}, ExtKeyUsageIPSECEndSystem},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}, ExtKeyUsageIPSECTunnel},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}, ExtKeyUsageIPSECUser},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, ExtKeyUsageTimeStamping},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, ExtKeyUsageOCSPSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}, ExtKeyUsageMicrosoftServerGatedCrypto},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}, ExtKeyUsageNetscapeServerGatedCrypto},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}, ExtKeyUsageMicrosoftCommercialCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}, ExtKeyUsageMicrosoftKernelCodeSigning},
}

// parseExtensions copies the BasicConstraints, KeyUsage, ExtKeyUsage and
// SubjectAltName extensions of x into c.
func parseExtensions(c *Certificate, x *wolfSSL.WOLFSSL_X509) error {
	cx := (*C.WOLFSSL_X509)(unsafe.Pointer(x))

	var isCA C.int
	if C.wolfx509_basic_constraints(cx, &isCA) != 0 {
		c.BasicConstraintsValid = true
		c.IsCA = isCA != 0
	}

	var usage C.uint
	if C.wolfx509_key_usage(cx, &usage) != 0 {
		c.KeyUsage = keyUsageFromWolfCrypt(int(usage))
	}

	exts, err := certExtensions(c.Raw)
	if err != nil {
		return err
	}
	if err := parseExtKeyUsage(c, exts); err != nil {
		return err
	}
	return parseSubjectAltName(c, exts)
}

// keyUsageFromWolfCrypt is the inverse of translateKeyUsage.
func keyUsageFromWolfCrypt(u int) KeyUsage {
	var out KeyUsage
	for _, m := range []struct {
		wc int
		ku KeyUsage
	}{
		{wcKeyUsageDigitalSignature, KeyUsageDigitalSignature},
		{wcKeyUsageContentCommit, KeyUsageContentCommitment},
		{wcKeyUsageKeyEncipherment, KeyUsageKeyEncipherment},
		{wcKeyUsageDataEncipherment, KeyUsageDataEncipherment},
		{wcKeyUsageKeyAgreement, KeyUsageKeyAgreement},
		{wcKeyUsageCertSign, KeyUsageCertSign},
		{wcKeyUsageCRLSign, KeyUsageCRLSign},
		{wcKeyUsageEncipherOnly, KeyUsageEncipherOnly},
		{wcKeyUsageDecipherOnly, KeyUsageDecipherOnly},
	} {
		if u&m.wc != 0 {
			out |= m.ku
		}
	}
	return out
}

// certExtension is one Extension of a DER certificate.
type certExtension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// certExtensions walks der directly, so a present but undecodable or empty
// extension cannot look absent the way it can through the wolfSSL accessors.
func certExtensions(der []byte) ([]certExtension, error) {
	var cert struct {
		TBS struct {
			Raw        asn1.RawContent
			Version    int `asn1:"optional,explicit,default:0,tag:0"`
			Serial     asn1.RawValue
			Signature  asn1.RawValue
			Issuer     asn1.RawValue
			Validity   asn1.RawValue
			Subject    asn1.RawValue
			PublicKey  asn1.RawValue
			IssuerUID  asn1.BitString  `asn1:"optional,tag:1"`
			SubjectUID asn1.BitString  `asn1:"optional,tag:2"`
			Extensions []certExtension `asn1:"optional,explicit,tag:3"`
		}
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: cannot walk certificate extensions", ErrInvalidCert)
	}
	return cert.TBS.Extensions, nil
}

// parseExtKeyUsage fills ExtKeyUsage and UnknownExtKeyUsage from exts in
// certificate order.
func parseExtKeyUsage(c *Certificate, exts []certExtension) error {
	seen := false
	for _, ext := range exts {
		if !ext.ID.Equal(oidExtKeyUsage) {
			continue
		}
		if seen {
			return fmt.Errorf("%w: duplicate extKeyUsage", ErrInvalidCert)
		}
		seen = true
		var oids []asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(ext.Value, &oids); err != nil || len(rest) != 0 {
			return fmt.Errorf("%w: malformed extKeyUsage", ErrInvalidCert)
		}
		if len(oids) == 0 {
			return fmt.Errorf("%w: empty extKeyUsage", ErrInvalidCert)
		}
		c.ExtKeyUsage = []ExtKeyUsage{}
		for _, oid := range oids {
			known := false
			for _, m := range extKeyUsageOIDs {
				if oid.Equal(m.oid) {
					c.ExtKeyUsage = append(c.ExtKeyUsage, m.eku)
					known = true
					break
				}
			}
			if !known {
				c.UnknownExtKeyUsage = append(c.UnknownExtKeyUsage, oid)
			}
		}
	}
	return nil
}

// parseSubjectAltName fills DNSNames, EmailAddresses and IPAddresses from
// exts in certificate order. Other GeneralName types are skipped, as
// crypto/x509 does; malformed DNS, email or IP entries are an error.
func parseSubjectAltName(c *Certificate, exts []certExtension) error {
	seen := false
	for _, ext := range exts {
		if !ext.ID.Equal(oidSubjectAltName) {
			continue
		}
		if seen {
			return fmt.Errorf("%w: duplicate subjectAltName", ErrInvalidCert)
		}
		seen = true
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &names); err != nil || len(rest) != 0 {
			return fmt.Errorf("%w: malformed subjectAltName", ErrInvalidCert)
		}
		if len(names) == 0 {
			return fmt.Errorf("%w: empty subjectAltName", ErrInvalidCert)
		}
		for _, gn := range names {
			if gn.Class != asn1.ClassContextSpecific {
				return fmt.Errorf("%w: malformed GeneralName", ErrInvalidCert)
			}
			switch gn.Tag {
			case 1, 2: // rfc822Name, dNSName
				name := string(gn.Bytes)
				if gn.IsCompound || !isIA5String(name) {
					return fmt.Errorf("%w: SAN %q is not an IA5String", ErrInvalidCert, name)
				}
				if gn.Tag == 2 {
					c.DNSNames = append(c.DNSNames, name)
				} else {
					c.EmailAddresses = append(c.EmailAddresses, name)
				}
			case 7: // iPAddress
				b := gn.Bytes
				if gn.IsCompound || (len(b) != net.IPv4len && len(b) != net.IPv6len) {
					return fmt.Errorf("%w: iPAddress SAN of length %d", ErrInvalidCert, len(b))
				}
				if len(b) == net.IPv6len && net.IP(b).To4() != nil {
					return fmt.Errorf("%w: IPv4-mapped iPAddress SAN", ErrInvalidCert)
				}
				c.IPAddresses = append(c.IPAddresses, append(net.IP(nil), b...))
			}
		}
	}
	return nil
}
