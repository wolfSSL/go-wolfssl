/* x509.go
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

// #include <wolfssl/options.h>
// #include <wolfssl/openssl/x509.h>
// #include <wolfssl/openssl/x509_vfy.h>
// #include <wolfssl/openssl/ssl.h>
// #include <wolfssl/openssl/stack.h>
// #include <wolfssl/openssl/bio.h>
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
// typedef struct WOLFSSL_X509_NAME {} WOLFSSL_X509_NAME;
// typedef struct WOLFSSL_X509_NAME_ENTRY {} WOLFSSL_X509_NAME_ENTRY;
// static WOLFSSL_X509_NAME* wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert) { return NULL; }
// static int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME* name) { return -174; }
// static WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_get_entry(WOLFSSL_X509_NAME* name, int loc) { return NULL; }
// static WOLFSSL_ASN1_OBJECT* wolfSSL_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY* ne) { return NULL; }
// static WOLFSSL_ASN1_STRING* wolfSSL_X509_NAME_ENTRY_get_data(WOLFSSL_X509_NAME_ENTRY* in) { return NULL; }
// static int wolfSSL_OBJ_obj2txt(char* buf, int buf_len, const WOLFSSL_ASN1_OBJECT* a, int no_name) { return -174; }
// static const unsigned char* wolfSSL_ASN1_STRING_get0_data(const WOLFSSL_ASN1_STRING* asn) { return NULL; }
// static int wolfSSL_ASN1_STRING_length(const WOLFSSL_ASN1_STRING* asn) { return -174; }
// #endif
import "C"
import (
    "unsafe"
)

type WOLFSSL_X509 = C.struct_WOLFSSL_X509
type WOLFSSL_X509_NAME = C.struct_WOLFSSL_X509_NAME
type WOLFSSL_X509_NAME_ENTRY = C.struct_WOLFSSL_X509_NAME_ENTRY
type WOLFSSL_ASN1_OBJECT = C.struct_WOLFSSL_ASN1_OBJECT
type WOLFSSL_ASN1_STRING = C.struct_WOLFSSL_ASN1_STRING

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
	return C.wolfSSL_X509_load_certificate_buffer((*C.byte)(unsafe.Pointer(&buff[0])), C.int(buffSz), C.int(certType))
}

func WolfSSL_X509_get_pubkey_buffer(cert *WOLFSSL_X509, out []byte, outLen *int) int {
	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	return int(C.wolfSSL_X509_get_pubkey_buffer(cert, outPtr, (*C.int)(unsafe.Pointer(outLen))))
}

func WolfSSL_X509_get_subject_name(cert *WOLFSSL_X509) *WOLFSSL_X509_NAME {
	return (*WOLFSSL_X509_NAME)(C.wolfSSL_X509_get_subject_name((*C.struct_WOLFSSL_X509)(cert)))
}

func WolfSSL_X509_NAME_oneline(name *WOLFSSL_X509_NAME, in []byte, sz int) string {
	var inPtr *C.char
	if len(in) > 0 {
		inPtr = (*C.char)(unsafe.Pointer(&in[0]))
	}
	result := C.wolfSSL_X509_NAME_oneline((*C.struct_WOLFSSL_X509_NAME)(name), inPtr, C.int(sz))
	if result != nil {
		return C.GoString(result)
	}
	return ""
}

func WolfSSL_X509_NAME_entry_count(name *WOLFSSL_X509_NAME) int {
	return int(C.wolfSSL_X509_NAME_entry_count((*C.struct_WOLFSSL_X509_NAME)(name)))
}

func WolfSSL_X509_NAME_get_entry(name *WOLFSSL_X509_NAME, loc int) *WOLFSSL_X509_NAME_ENTRY {
	return (*WOLFSSL_X509_NAME_ENTRY)(C.wolfSSL_X509_NAME_get_entry((*C.struct_WOLFSSL_X509_NAME)(name), C.int(loc)))
}

func WolfSSL_X509_NAME_ENTRY_get_object(ne *WOLFSSL_X509_NAME_ENTRY) *WOLFSSL_ASN1_OBJECT {
	return (*WOLFSSL_ASN1_OBJECT)(C.wolfSSL_X509_NAME_ENTRY_get_object((*C.struct_WOLFSSL_X509_NAME_ENTRY)(ne)))
}

func WolfSSL_X509_NAME_ENTRY_get_data(in *WOLFSSL_X509_NAME_ENTRY) *WOLFSSL_ASN1_STRING {
	return (*WOLFSSL_ASN1_STRING)(C.wolfSSL_X509_NAME_ENTRY_get_data((*C.struct_WOLFSSL_X509_NAME_ENTRY)(in)))
}

func WolfSSL_OBJ_obj2txt(buf []byte, bufLen int, a *WOLFSSL_ASN1_OBJECT, noName int) int {
	var bufPtr *C.char
	if len(buf) > 0 {
		bufPtr = (*C.char)(unsafe.Pointer(&buf[0]))
	}
	return int(C.wolfSSL_OBJ_obj2txt(bufPtr, C.int(bufLen), (*C.struct_WOLFSSL_ASN1_OBJECT)(a), C.int(noName)))
}

func WolfSSL_ASN1_STRING_get0_data(asn *WOLFSSL_ASN1_STRING) []byte {
	data := C.wolfSSL_ASN1_STRING_get0_data((*C.struct_WOLFSSL_ASN1_STRING)(asn))
	if data == nil {
		return nil
	}
	length := int(C.wolfSSL_ASN1_STRING_length((*C.struct_WOLFSSL_ASN1_STRING)(asn)))
	if length <= 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(length))
}

func WolfSSL_ASN1_STRING_length(asn *WOLFSSL_ASN1_STRING) int {
	return int(C.wolfSSL_ASN1_STRING_length((*C.struct_WOLFSSL_ASN1_STRING)(asn)))
}

