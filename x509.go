/* x509.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

// #include <wolfssl/options.h>
// #include <wolfssl/openssl/x509.h>
// #include <wolfssl/openssl/x509v3.h>
// #include <wolfssl/openssl/x509_vfy.h>
// #include <wolfssl/openssl/ssl.h>
// #include <wolfssl/openssl/stack.h>
// #include <wolfssl/openssl/bio.h>
// #include <wolfssl/openssl/pem.h>
// #include <wolfssl/openssl/asn1.h>
// #include <wolfssl/openssl/objects.h>
// #include <wolfssl/openssl/crypto.h>
// #ifndef OPENSSL_ALL
// typedef struct WOLFSSL_X509 {} WOLFSSL_X509;
// typedef struct WOLFSSL_X509_STORE {} WOLFSSL_X509_STORE;
// typedef struct WOLFSSL_STACK {} WOLFSSL_STACK;
// static WOLFSSL_X509_STORE* X509_STORE_new(void) { return NULL; }
// static void X509_STORE_free(WOLFSSL_X509_STORE* s) { (void)s; }
// static int X509_STORE_load_locations(WOLFSSL_X509_STORE* s, const char* file, const char* path) { return -174; }
// static WOLFSSL_STACK* sk_X509_new_null(void) { return NULL; }
// static int sk_X509_push(WOLFSSL_STACK* sk, WOLFSSL_X509* cert) { return -174; }
// static void sk_X509_free(WOLFSSL_STACK* sk) { (void)sk; }
// static WOLFSSL_X509_STORE_CTX* X509_STORE_CTX_new(void) { return NULL; }
// static void X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX* ctx) { (void)ctx; }
// static int X509_STORE_CTX_init(WOLFSSL_X509_STORE_CTX* ctx, WOLFSSL_X509_STORE* store,
//                                 WOLFSSL_X509* cert, WOLFSSL_STACK* chain) { return -174; }
// static int X509_verify_cert(WOLFSSL_X509_STORE_CTX* ctx) { return -174; }
// static WOLFSSL_X509* wolfSSL_X509_load_certificate_buffer(const unsigned char* buff, int sz, int type) { return NULL; }
// static int wolfSSL_X509_get_pubkey_buffer(WOLFSSL_X509* x509, unsigned char* buf, int* bufSz) { return -174; }
// typedef struct WOLFSSL_BIO {} WOLFSSL_BIO;
// static WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(const void* buf, int len) { return NULL; }
// static int wolfSSL_BIO_free(WOLFSSL_BIO* bio) { return -174; }
// extern void wolfSSL_X509_free(WOLFSSL_X509* x509);
// extern void wolfSSL_OPENSSL_free(void* p);
// static void wolfSSL_X509_dummy_padding(void) {}
// static WOLFSSL_ASN1_OBJECT* wolfSSL_d2i_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT** a, const unsigned char** der, long length) { return NULL; }
// int wolfSSL_ASN1_get_object(const unsigned char** in, long* objLen, int* tag, int* cls, long inLen) { return -174; }
// static void wolfSSL_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT* obj) { (void)obj; }
// static WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name) { return NULL; }
// static int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a, const WOLFSSL_ASN1_OBJECT* b) { return -174; }
// #endif
// /* When OPENSSL_ALL is on the header declares wolfSSL_OBJ_txt2obj, but the
//  * implementation in src/ssl.c is gated by WOLFSSL_CERT_EXT && WOLFSSL_CERT_GEN.
//  * Provide a fallback so configs without certext/certgen still link. */
// #if defined(OPENSSL_ALL) && (!defined(WOLFSSL_CERT_EXT) || !defined(WOLFSSL_CERT_GEN))
// WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name) {
//      (void)s; (void)no_name;
//      return NULL; /* OBJ_txt2obj returns a pointer; NULL is its error sentinel. */
// }
// #endif
// /* Helper to fetch the ASN1_TIME-printed string for NotBefore/NotAfter via
//  * a temporary BIO. Returns length written (<= outSz) or 0 on error. */
// #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
// static int wolfx509_asn1_time_print(const WOLFSSL_ASN1_TIME* t, char* out, int outSz) {
//     WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
//     if (bio == NULL) return 0;
//     if (wolfSSL_ASN1_TIME_print(bio, t) != 1) { wolfSSL_BIO_free(bio); return 0; }
//     int n = wolfSSL_BIO_read(bio, out, outSz - 1);
//     wolfSSL_BIO_free(bio);
//     if (n <= 0) return 0;
//     out[n] = '\0';
//     return n;
// }
// /* Fetch a single NID text value (e.g. CommonName) into a Go-owned buffer. */
// static int wolfx509_name_get_text_by_nid(WOLFSSL_X509_NAME* name, int nid, char* out, int outSz) {
//     if (name == NULL) return 0;
//     int n = wolfSSL_X509_NAME_get_text_by_NID(name, nid, out, outSz);
//     if (n < 0) return 0;
//     return n;
// }
// /* Extract serial number bytes as raw big-endian integer bytes. */
// static int wolfx509_get_serial_bytes(WOLFSSL_X509* x, unsigned char* out, int outSz) {
//     if (x == NULL) return 0;
//     int len = outSz;
//     int ret = wolfSSL_X509_get_serial_number(x, out, &len);
//     if (ret != WOLFSSL_SUCCESS) return 0;
//     return len;
// }
// /* Extract the keyIdentifier bytes from the AuthorityKeyIdentifier
//  * extension (RFC 5280 §4.2.1.1). Returns the length copied or 0 if
//  * the extension is absent. */
// static int wolfx509_get_authority_key_id(WOLFSSL_X509* x, unsigned char* out, int outSz) {
//     if (x == NULL) return 0;
//     WOLFSSL_AUTHORITY_KEYID* akid = (WOLFSSL_AUTHORITY_KEYID*)wolfSSL_X509_get_ext_d2i(
//         x, NID_authority_key_identifier, NULL, NULL);
//     if (akid == NULL) return 0;
//     int n = 0;
//     /* wolfSSL populates the AKI keyIdentifier bytes inside the
//      * issuer ASN1_OBJECT's obj/objSz fields (see
//      * wolfSSL_X509_get_ext_d2i → AUTH_KEY_OID in wolfssl/src/x509.c),
//      * not in the keyid ASN1_STRING that the OpenSSL struct layout
//      * suggests. Read from issuer->obj accordingly. */
//     if (akid->issuer != NULL && akid->issuer->obj != NULL) {
//         int len = (int)akid->issuer->objSz;
//         if (len > 0 && len <= outSz) {
//             memcpy(out, akid->issuer->obj, len);
//             n = len;
//         }
//     }
//     wolfSSL_AUTHORITY_KEYID_free(akid);
//     return n;
// }
// #else
// static int wolfx509_asn1_time_print(const WOLFSSL_ASN1_TIME* t, char* out, int outSz) { (void)t; (void)out; (void)outSz; return 0; }
// static char* wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME* name, char* in, int sz) { (void)name; (void)in; (void)sz; return NULL; }
// static int wolfx509_name_get_text_by_nid(WOLFSSL_X509_NAME* name, int nid, char* out, int outSz) { (void)name; (void)nid; (void)out; (void)outSz; return 0; }
// static char* wolfSSL_X509_get_subjectCN(WOLFSSL_X509* x) { (void)x; return NULL; }
// static int wolfx509_get_serial_bytes(WOLFSSL_X509* x, unsigned char* out, int outSz) { (void)x; (void)out; (void)outSz; return 0; }
// static int wolfx509_get_authority_key_id(WOLFSSL_X509* x, unsigned char* out, int outSz) { (void)x; (void)out; (void)outSz; return 0; }
// static WOLFSSL_X509_NAME* wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert) { (void)cert; return NULL; }
// static WOLFSSL_X509_NAME* wolfSSL_X509_get_issuer_name(WOLFSSL_X509* cert) { (void)cert; return NULL; }
// static WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(const WOLFSSL_X509* x) { (void)x; return NULL; }
// static WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(const WOLFSSL_X509* x) { (void)x; return NULL; }
// #endif
// #include <string.h>
import "C"
import (
    "sync"
    "unsafe"
)

var bioBufMap sync.Map

type WOLFSSL_X509 = C.struct_WOLFSSL_X509
type WOLFSSL_BIO = C.struct_WOLFSSL_BIO
type WOLFSSL_ASN1_OBJECT = C.struct_WOLFSSL_ASN1_OBJECT
type WOLFSSL_X509_NAME = C.struct_WOLFSSL_X509_NAME
type WOLFSSL_CERT_MANAGER = C.struct_WOLFSSL_CERT_MANAGER

// X509_STORE wrappers
func WolfSSL_X509_STORE_new() *C.WOLFSSL_X509_STORE {
	return C.X509_STORE_new()
}

func WolfSSL_X509_STORE_free(store *C.WOLFSSL_X509_STORE) {
	C.X509_STORE_free(store)
}

func WolfSSL_X509_STORE_load_locations(store *C.WOLFSSL_X509_STORE, capath string) int {
	cStr := C.CString(capath)
	defer C.free(unsafe.Pointer(cStr))
	return int(C.X509_STORE_load_locations(store, nil, cStr))
}

func WolfSSL_X509_STORE_load_file(store *C.WOLFSSL_X509_STORE, cafile string) int {
	cStr := C.CString(cafile)
	defer C.free(unsafe.Pointer(cStr))
	return int(C.X509_STORE_load_locations(store, cStr, nil))
}

// WOLFSSL_STACK (used as sk_X509*)
func WolfSSL_sk_X509_new_null() *C.WOLFSSL_STACK {
	return C.sk_X509_new_null()
}

func WolfSSL_sk_X509_push(stack *C.WOLFSSL_STACK, cert *C.WOLFSSL_X509) int {
	return int(C.sk_X509_push(stack, cert))
}

func WolfSSL_sk_X509_free(stack *C.WOLFSSL_STACK) {
	C.sk_X509_free(stack)
}

// X509_STORE_CTX
func WolfSSL_X509_STORE_CTX_new() *C.WOLFSSL_X509_STORE_CTX {
	return C.X509_STORE_CTX_new()
}

func WolfSSL_X509_STORE_CTX_free(ctx *C.WOLFSSL_X509_STORE_CTX) {
	C.X509_STORE_CTX_free(ctx)
}

func WolfSSL_X509_STORE_CTX_init(ctx *C.WOLFSSL_X509_STORE_CTX, store *C.WOLFSSL_X509_STORE, cert *C.WOLFSSL_X509, chain *C.WOLFSSL_STACK) int {
	return int(C.X509_STORE_CTX_init(ctx, store, cert, chain))
}

func WolfSSL_X509_verify_cert(ctx *C.WOLFSSL_X509_STORE_CTX) int {
	return int(C.X509_verify_cert(ctx))
}

func WolfSSL_X509_load_certificate_buffer(buff []byte, buffSz int, certType int) *C.WOLFSSL_X509 {
	if buffSz < 0 || buffSz > len(buff) || len(buff) == 0 { return nil }
	return C.wolfSSL_X509_load_certificate_buffer((*C.byte)(unsafe.Pointer(&buff[0])), C.int(buffSz), C.int(certType))
}

func WolfSSL_X509_get_pubkey_buffer(cert *WOLFSSL_X509, out []byte, outLen *int) int {
	if outLen == nil { return BAD_FUNC_ARG }
	if len(out) > 0 && (*outLen < 0 || *outLen > len(out)) { return BAD_FUNC_ARG }
	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	cOutLen := C.int(*outLen)
	ret := int(C.wolfSSL_X509_get_pubkey_buffer(cert, outPtr, &cOutLen))
	*outLen = int(cOutLen)
	return ret
}

func WolfSSL_BIO_new_mem_buf(buf []byte, bufLen int) *WOLFSSL_BIO {
	if bufLen <= 0 || bufLen > len(buf) {
		return nil
	}
	cBuf := C.CBytes(buf[:bufLen])
	bio := (*WOLFSSL_BIO)(C.wolfSSL_BIO_new_mem_buf(cBuf, C.int(bufLen)))
	if bio != nil {
		bioBufMap.Store(unsafe.Pointer(bio), cBuf)
	} else {
		C.free(cBuf)
	}
	return bio
}

func WolfSSL_BIO_free(bio *WOLFSSL_BIO) int {
	if bio == nil {
		return 1
	}
	cBuf, hasBuf := bioBufMap.LoadAndDelete(unsafe.Pointer(bio))
	// Free the BIO before releasing the backing C buffer so teardown never
	// observes freed backing storage.
	ret := int(C.wolfSSL_BIO_free((*C.struct_WOLFSSL_BIO)(bio)))
	if hasBuf {
		C.free(cBuf.(unsafe.Pointer))
	}
	return ret
}

func WolfSSL_i2d_X509(x509 *WOLFSSL_X509, out *[]byte) int {
	var outPtr *C.uchar
	result := int(C.wolfSSL_i2d_X509((*C.struct_WOLFSSL_X509)(x509), &outPtr))
	if result > 0 && outPtr != nil {
		*out = C.GoBytes(unsafe.Pointer(outPtr), C.int(result))
		C.wolfSSL_OPENSSL_free(unsafe.Pointer(outPtr))
	}
	return result
}

func WolfSSL_X509_free(x509 *WOLFSSL_X509) {
	C.wolfSSL_X509_free((*C.struct_WOLFSSL_X509)(x509))
}

func WolfSSL_ASN1_get_object(in *[]byte, objLen *int, tag *int, cls *int, inLen int) int {
	if len(*in) == 0 || inLen < 0 || inLen > len(*in) {
		return -1
	}

	// Copy the input to C memory so the pointer-to-pointer indirection
	// never holds a Go pointer (cgo rule: Go memory passed to C must not
	// contain Go pointers).
	cBuf := C.CBytes(*in)
	defer C.free(cBuf)
	cStart := (*C.uchar)(cBuf)
	cInPtr := cStart

	var cLen C.long
	var cTag C.int
	var cCls C.int

	result := int(C.wolfSSL_ASN1_get_object(&cInPtr, &cLen, &cTag, &cCls, C.long(inLen)))

	if result >= 0 {
		offset := uintptr(unsafe.Pointer(cInPtr)) - uintptr(unsafe.Pointer(cStart))
		if offset > uintptr(len(*in)) { return -1 }
		*in = (*in)[offset:]
		*objLen = int(cLen)
		*tag = int(cTag)
		*cls = int(cCls)
	}

	return result
}

func WolfSSL_d2i_ASN1_OBJECT(a **WOLFSSL_ASN1_OBJECT, der *[]byte, length int) *WOLFSSL_ASN1_OBJECT {
	if len(*der) == 0 || length < 0 || length > len(*der) {
		return nil
	}

	var aPtr **C.struct_WOLFSSL_ASN1_OBJECT
	if a != nil {
		aPtr = (**C.struct_WOLFSSL_ASN1_OBJECT)(unsafe.Pointer(a))
	}

	cBuf := C.CBytes(*der)
	defer C.free(cBuf)
	cStart := (*C.uchar)(cBuf)
	cDerPtr := cStart

	result := (*WOLFSSL_ASN1_OBJECT)(C.wolfSSL_d2i_ASN1_OBJECT(aPtr, &cDerPtr, C.long(length)))

	if result != nil {
		offset := uintptr(unsafe.Pointer(cDerPtr)) - uintptr(unsafe.Pointer(cStart))
		if offset > uintptr(len(*der)) { return nil }
		*der = (*der)[offset:]
	}

	return result
}

func WolfSSL_ASN1_OBJECT_free(obj *WOLFSSL_ASN1_OBJECT) {
	C.wolfSSL_ASN1_OBJECT_free((*C.struct_WOLFSSL_ASN1_OBJECT)(obj))
}

func WolfSSL_OBJ_txt2obj(s string, noName int) *WOLFSSL_ASN1_OBJECT {
	cStr := C.CString(s)
	defer C.free(unsafe.Pointer(cStr))
	return (*WOLFSSL_ASN1_OBJECT)(C.wolfSSL_OBJ_txt2obj(cStr, C.int(noName)))
}

func WolfSSL_OBJ_cmp(a *WOLFSSL_ASN1_OBJECT, b *WOLFSSL_ASN1_OBJECT) int {
	return int(C.wolfSSL_OBJ_cmp((*C.struct_WOLFSSL_ASN1_OBJECT)(a), (*C.struct_WOLFSSL_ASN1_OBJECT)(b)))
}

// -----------------------------------------------------------------------------
// Extended X.509 bindings used by the wolfx509 Go package.
// -----------------------------------------------------------------------------

// WolfSSL_d2i_X509 parses a DER-encoded cert. Returns nil on error. The caller
// must free the result with WolfSSL_X509_free.
func WolfSSL_d2i_X509(der []byte) *WOLFSSL_X509 {
	if len(der) == 0 {
		return nil
	}
	in := (*C.uchar)(unsafe.Pointer(&der[0]))
	pp := &in
	return C.wolfSSL_d2i_X509(nil, (**C.uchar)(unsafe.Pointer(pp)), C.int(len(der)))
}

// WolfSSL_X509_get_subject_name returns the Subject DN. The returned pointer
// is owned by the certificate and must not be freed separately.
func WolfSSL_X509_get_subject_name(x *WOLFSSL_X509) *WOLFSSL_X509_NAME {
	return C.wolfSSL_X509_get_subject_name(x)
}

// WolfSSL_X509_get_issuer_name returns the Issuer DN.
func WolfSSL_X509_get_issuer_name(x *WOLFSSL_X509) *WOLFSSL_X509_NAME {
	return C.wolfSSL_X509_get_issuer_name(x)
}

// WolfSSL_X509_NAME_oneline formats the DN as a single line. Passing
// NULL/0 makes wolfSSL allocate a buffer sized for the full DN, so
// unusually long subjects don't truncate. The buffer is freed via
// wolfSSL_OPENSSL_free.
func WolfSSL_X509_NAME_oneline(name *WOLFSSL_X509_NAME) string {
	if name == nil {
		return ""
	}
	cstr := C.wolfSSL_X509_NAME_oneline(name, nil, 0)
	if cstr == nil {
		return ""
	}
	defer C.wolfSSL_OPENSSL_free(unsafe.Pointer(cstr))
	return C.GoString(cstr)
}

// WolfSSL_X509_NAME_get_text_by_NID reads the text value for the given NID
// (e.g. NID_commonName) from name. Returns "" if not present. Uses a
// length-query call (NULL buffer) followed by a sized fetch so very
// long attribute values aren't silently truncated.
func WolfSSL_X509_NAME_get_text_by_NID(name *WOLFSSL_X509_NAME, nid int) string {
	n := C.wolfx509_name_get_text_by_nid(name, C.int(nid), nil, 0)
	if n <= 0 {
		return ""
	}
	buf := make([]byte, n+1)
	got := C.wolfx509_name_get_text_by_nid(name, C.int(nid),
		(*C.char)(unsafe.Pointer(&buf[0])), C.int(n+1))
	if got <= 0 {
		return ""
	}
	return string(buf[:got])
}

// NIDs we need. Values from wolfSSL's oid_sum.h / objects.h.
const (
	NID_commonName     = 13
	NID_countryName    = 14
	NID_organizationName = 17
	NID_organizationalUnitName = 18
)

// WolfSSL_X509_get_subjectCN returns the CN from the cert subject, or "".
// wolfSSL returns an internal pointer into the cert's subject string —
// no allocation, no truncation, valid for the cert's lifetime.
func WolfSSL_X509_get_subjectCN(x *WOLFSSL_X509) string {
	if x == nil {
		return ""
	}
	cn := C.wolfSSL_X509_get_subjectCN(x)
	if cn == nil {
		return ""
	}
	return C.GoString(cn)
}

// WolfSSL_X509_get_notBefore_str returns the NotBefore time as a printable
// string (e.g. "Apr 16 14:22:03 2026 GMT"). Returns "" on error.
func WolfSSL_X509_get_notBefore_str(x *WOLFSSL_X509) string {
	t := C.wolfSSL_X509_get_notBefore(x)
	if t == nil {
		return ""
	}
	var buf [64]C.char
	n := C.wolfx509_asn1_time_print(t, &buf[0], C.int(len(buf)))
	if n <= 0 {
		return ""
	}
	return C.GoStringN(&buf[0], n)
}

// WolfSSL_X509_get_notAfter_str returns the NotAfter time as a printable string.
func WolfSSL_X509_get_notAfter_str(x *WOLFSSL_X509) string {
	t := C.wolfSSL_X509_get_notAfter(x)
	if t == nil {
		return ""
	}
	var buf [64]C.char
	n := C.wolfx509_asn1_time_print(t, &buf[0], C.int(len(buf)))
	if n <= 0 {
		return ""
	}
	return C.GoStringN(&buf[0], n)
}

// WolfSSL_X509_get_serial_bytes returns the big-endian serial number bytes.
func WolfSSL_X509_get_serial_bytes(x *WOLFSSL_X509) []byte {
	var buf [128]byte
	n := C.wolfx509_get_serial_bytes(x, (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return nil
	}
	out := make([]byte, int(n))
	copy(out, buf[:n])
	return out
}

// WolfSSL_X509_get_authority_key_id returns the raw bytes of the
// keyIdentifier field of the AuthorityKeyIdentifier extension (RFC 5280
// §4.2.1.1), or nil if the cert has no AKI extension. For issuers that
// use the SHA-1 of the subject public key the result is 20 bytes, which
// is what ACME's ARI path needs to build the {AKI}.{Serial} identifier.
func WolfSSL_X509_get_authority_key_id(x *WOLFSSL_X509) []byte {
	// Per RFC 5280 the keyIdentifier is nearly always a 160-bit hash;
	// 64 bytes is comfortably above that worst case.
	var buf [64]byte
	n := C.wolfx509_get_authority_key_id(x, (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return nil
	}
	out := make([]byte, int(n))
	copy(out, buf[:n])
	return out
}

// WolfSSL_X509_check_host returns 1 if host matches the cert, 0 otherwise.
func WolfSSL_X509_check_host(x *WOLFSSL_X509, host string) int {
	if host == "" {
		return 0
	}
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))
	return int(C.wolfSSL_X509_check_host(x, cHost, C.size_t(len(host)), 0, nil))
}

// -----------------------------------------------------------------------------
// WOLFSSL_CERT_MANAGER wrappers (used as CertPool backend by wolfx509).
// -----------------------------------------------------------------------------

// WolfSSL_CertManagerNew creates a new cert manager. Free with
// WolfSSL_CertManagerFree.
func WolfSSL_CertManagerNew() *WOLFSSL_CERT_MANAGER {
	return C.wolfSSL_CertManagerNew()
}

// WolfSSL_CertManagerFree releases a cert manager.
func WolfSSL_CertManagerFree(cm *WOLFSSL_CERT_MANAGER) {
	C.wolfSSL_CertManagerFree(cm)
}

// WolfSSL_CertManagerLoadCABuffer loads CA certs (PEM or DER) into the manager.
// fileType is SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.
func WolfSSL_CertManagerLoadCABuffer(cm *WOLFSSL_CERT_MANAGER, buf []byte, fileType int) int {
	if len(buf) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wolfSSL_CertManagerLoadCABuffer(cm,
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.long(len(buf)), C.int(fileType)))
}

// WolfSSL_CertManagerVerifyBuffer verifies a DER-encoded cert against the
// CAs loaded into the manager. Returns WOLFSSL_SUCCESS (1) on success.
func WolfSSL_CertManagerVerifyBuffer(cm *WOLFSSL_CERT_MANAGER, der []byte) int {
	if len(der) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wolfSSL_CertManagerVerifyBuffer(cm,
		(*C.uchar)(unsafe.Pointer(&der[0])),
		C.long(len(der)), C.int(SSL_FILETYPE_ASN1)))
}
