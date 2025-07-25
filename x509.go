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
// int wolfSSL_i2d_X509(WOLFSSL_X509* x509, unsigned char** out) { return -174; }
// static void wolfSSL_X509_free(WOLFSSL_X509* x509) { (void)x509; }
// static WOLFSSL_ASN1_OBJECT* wolfSSL_d2i_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT** a, const unsigned char** der, long length) { return NULL; }
// int wolfSSL_ASN1_get_object(const unsigned char** in, long* objLen, int* tag, int* cls, long inLen) { return -174; }
// static void wolfSSL_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT* obj) { (void)obj; }
// static WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name) { return NULL; }
// static int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a, const WOLFSSL_ASN1_OBJECT* b) { return -174; }
// #endif
import "C"
import (
    "unsafe"
)

type WOLFSSL_X509 = C.struct_WOLFSSL_X509
type WOLFSSL_BIO = C.struct_WOLFSSL_BIO
type WOLFSSL_ASN1_OBJECT = C.struct_WOLFSSL_ASN1_OBJECT

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

func WolfSSL_BIO_new_mem_buf(buf []byte, bufLen int) *WOLFSSL_BIO {
	var bufPtr *C.char
	if bufLen > 0 && bufLen <= len(buf) {
		bufPtr = (*C.char)(unsafe.Pointer(&buf[0]))
	}
	return (*WOLFSSL_BIO)(C.wolfSSL_BIO_new_mem_buf(unsafe.Pointer(bufPtr), C.int(bufLen)))
}

func WolfSSL_BIO_free(bio *WOLFSSL_BIO) int {
	return int(C.wolfSSL_BIO_free((*C.struct_WOLFSSL_BIO)(bio)))
}

func WolfSSL_i2d_X509(x509 *WOLFSSL_X509, out *[]byte) int {
	var outPtr *C.uchar
	result := int(C.wolfSSL_i2d_X509((*C.struct_WOLFSSL_X509)(x509), &outPtr))
	if result > 0 && outPtr != nil {
		*out = C.GoBytes(unsafe.Pointer(outPtr), C.int(result))
	}
	return result
}

func WolfSSL_X509_free(x509 *WOLFSSL_X509) {
	C.wolfSSL_X509_free((*C.struct_WOLFSSL_X509)(x509))
}

func WolfSSL_ASN1_get_object(in *[]byte, objLen *int, tag *int, cls *int, inLen int) int {
	if len(*in) == 0 {
		return -1
	}
	
	cInPtr := (*C.uchar)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0)))))
	defer C.free(unsafe.Pointer(cInPtr))
	
	inPtr := (*C.uchar)(unsafe.Pointer(&(*in)[0]))
	*(**C.uchar)(unsafe.Pointer(cInPtr)) = inPtr
	
	var cLen C.long
	var cTag C.int
	var cCls C.int
	
	result := int(C.wolfSSL_ASN1_get_object((**C.uchar)(unsafe.Pointer(cInPtr)), &cLen, &cTag, &cCls, C.long(inLen)))
	
	if result >= 0 {
		newPtr := *(**C.uchar)(unsafe.Pointer(cInPtr))
		offset := uintptr(unsafe.Pointer(newPtr)) - uintptr(unsafe.Pointer(&(*in)[0]))
		*in = (*in)[offset:]
		*objLen = int(cLen)
		*tag = int(cTag)
		*cls = int(cCls)
	}
	
	return result
}

func WolfSSL_d2i_ASN1_OBJECT(a **WOLFSSL_ASN1_OBJECT, der *[]byte, length int) *WOLFSSL_ASN1_OBJECT {
	if len(*der) == 0 {
		return nil
	}
	
	var aPtr **C.struct_WOLFSSL_ASN1_OBJECT
	if a != nil {
		aPtr = (**C.struct_WOLFSSL_ASN1_OBJECT)(unsafe.Pointer(a))
	}
	
	cDerPtr := (*C.uchar)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0)))))
	defer C.free(unsafe.Pointer(cDerPtr))
	
	derPtr := (*C.uchar)(unsafe.Pointer(&(*der)[0]))
	*(**C.uchar)(unsafe.Pointer(cDerPtr)) = derPtr
	
	result := (*WOLFSSL_ASN1_OBJECT)(C.wolfSSL_d2i_ASN1_OBJECT(aPtr, (**C.uchar)(unsafe.Pointer(cDerPtr)), C.long(length)))
	
	if result != nil {
		newPtr := *(**C.uchar)(unsafe.Pointer(cDerPtr))
		offset := uintptr(unsafe.Pointer(newPtr)) - uintptr(unsafe.Pointer(&(*der)[0]))
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

