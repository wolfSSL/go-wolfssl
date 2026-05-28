/* ssl.go
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
// #include <wolfssl/ssl.h>
// #include <stdlib.h>
// #include <string.h>
//
// #include <wolfssl/wolfio.h>
//
// /* SNI request helper */
// #ifdef HAVE_SNI
// static int ssl_SNI_GetRequest(WOLFSSL* ssl, char* out, int outSz) {
//     void* data = NULL;
//     unsigned short sz = wolfSSL_SNI_GetRequest(ssl, 0, &data);
//     if (data == NULL || sz == 0) return 0;
//     if ((int)sz >= outSz) sz = (unsigned short)(outSz - 1);
//     memcpy(out, data, sz);
//     out[sz] = '\0';
//     return (int)sz;
// }
// #else
// static int ssl_SNI_GetRequest(WOLFSSL* ssl, char* out, int outSz) {
//     (void)ssl; (void)out; (void)outSz; return 0;
// }
// #endif
// #ifdef OPENSSL_ALL
// #include <wolfssl/openssl/x509.h>
// #endif
// #if !defined(OPENSSL_EXTRA) && !defined(OPENSSL_ALL)
// void wolfSSL_OPENSSL_free(void* p) { free(p); }
// void wolfSSL_X509_free(WOLFSSL_X509* x509) { (void)x509; }
// #endif
// #ifdef NO_PSK
// typedef unsigned int (*pskCb)();
// int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint) {
//      return -174;
// }
// void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// void wolfSSL_CTX_set_psk_server_tls13_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// void wolfSSL_CTX_set_psk_client_tls13_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// #endif
// #ifndef WOLFSSL_DTLS
// WOLFSSL_METHOD*  wolfDTLSv1_2_server_method(void) {
//      return NULL;
// }
// WOLFSSL_METHOD*  wolfDTLSv1_2_client_method(void) {
//      return NULL;
// }
// void* wolfSSL_dtls_create_peer(int port, char* ip) {
//      return NULL;
// }
// int wolfSSL_dtls_free_peer(void* addr) {
//      return -174;
// }
// #endif
// #ifndef WOLFSSL_DTLS13
// WOLFSSL_METHOD*  wolfDTLSv1_3_server_method(void) {
//      return NULL;
// }
// WOLFSSL_METHOD*  wolfDTLSv1_3_client_method(void) {
//      return NULL;
// }
// #endif
// #ifndef HAVE_WRITE_DUP
// WOLFSSL* wolfSSL_write_dup(WOLFSSL* ssl) {
//      return NULL;
// }
// #endif
// #if !defined(OPENSSL_EXTRA)
// int wolfSSL_CTX_set_min_proto_version(WOLFSSL_CTX* ctx, int v) {
//      (void)ctx; (void)v; return -174;
// }
// int wolfSSL_CTX_set_max_proto_version(WOLFSSL_CTX* ctx, int v) {
//      (void)ctx; (void)v; return -174;
// }
// #endif
// #ifndef SESSION_CERTS
// WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl) {
//      return NULL;
// }
// int wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain) {
//      return 0;
// }
// unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx) {
//      return NULL;
// }
// int wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx) {
//      return 0;
// }
// #endif
// #ifndef HAVE_ALPN
// int wolfSSL_UseALPN(WOLFSSL* ssl, char* protocol_name_list,
//                     unsigned int protocol_name_listSz, unsigned char options) {
//      (void)ssl; (void)protocol_name_list;
//      (void)protocol_name_listSz; (void)options;
//      return NOT_COMPILED_IN;
// }
// int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char** protocol_name,
//                              unsigned short* size) {
//      (void)ssl; (void)protocol_name; (void)size;
//      return NOT_COMPILED_IN;
// }
// int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char** list,
//                                  unsigned short* listSz) {
//      (void)ssl; (void)list; (void)listSz;
//      return NOT_COMPILED_IN;
// }
// int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char** list) {
//      (void)ssl; (void)list;
//      return NOT_COMPILED_IN;
// }
// #endif
import "C"
import (
    "unsafe"
)

const SSL_FILETYPE_PEM = 1
const SSL_FILETYPE_ASN1 = 2
const WOLFSSL_SUCCESS  = 1

type WOLFSSL = C.struct_WOLFSSL
type WOLFSSL_CTX = C.struct_WOLFSSL_CTX

func WolfSSL_Init() {
    C.wolfSSL_Init()
}

func WolfSSL_Cleanup() {
    C.wolfSSL_Cleanup()
}

func WolfSSL_CTX_new(method *C.struct_WOLFSSL_METHOD) *C.struct_WOLFSSL_CTX {
    return C.wolfSSL_CTX_new(method)
}

func WolfSSL_CTX_free(ctx *C.struct_WOLFSSL_CTX) {
    C.wolfSSL_CTX_free(ctx)
}

func WolfSSL_CTX_set_cipher_list(ctx *C.struct_WOLFSSL_CTX, list string) int {
    c_list := C.CString(list)
    defer C.free(unsafe.Pointer(c_list))
    return int(C.wolfSSL_CTX_set_cipher_list(ctx, c_list))
}

func WolfSSL_new(ctx *C.struct_WOLFSSL_CTX) *C.struct_WOLFSSL {
    return C.wolfSSL_new(ctx)
}

func WolfSSL_write_dup(ssl *C.struct_WOLFSSL) *C.struct_WOLFSSL {
    return C.wolfSSL_write_dup(ssl)
}

func WolfSSL_connect(ssl *C.struct_WOLFSSL) int {
    return int(C.wolfSSL_connect(ssl))
}

func WolfSSL_shutdown(ssl *C.struct_WOLFSSL) {
    C.wolfSSL_shutdown(ssl)
}

func WolfSSL_free(ssl *C.struct_WOLFSSL) {
    C.wolfSSL_free(ssl)
}

func WolfTLSv1_2_server_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfTLSv1_2_server_method()
}

func WolfTLSv1_2_client_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfTLSv1_2_client_method()
}

func WolfTLSv1_3_server_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfTLSv1_3_server_method()
}

func WolfTLSv1_3_client_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfTLSv1_3_client_method()
}

func WolfDTLSv1_2_server_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfDTLSv1_2_server_method()
}

func WolfDTLSv1_2_client_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfDTLSv1_2_client_method()
}

func WolfDTLSv1_3_server_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfDTLSv1_3_server_method()
}

func WolfDTLSv1_3_client_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfDTLSv1_3_client_method()
}

func WolfSSL_dtls_create_peer(port int, ip string) unsafe.Pointer {
    c_ip := C.CString(ip)
    defer C.free(unsafe.Pointer(c_ip))
    return C.wolfSSL_dtls_create_peer(C.int(port), c_ip)
}

func WolfSSL_dtls_set_peer(ssl *C.struct_WOLFSSL, addr unsafe.Pointer, peerSz int) int {
    return int(C.wolfSSL_dtls_set_peer(ssl, addr, C.uint(peerSz)))
}

func WolfSSL_dtls_free_peer(addr unsafe.Pointer) int {
    return int(C.wolfSSL_dtls_free_peer(addr))
}

func WolfSSL_CTX_set_psk_server_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
    C.wolfSSL_CTX_set_psk_server_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_set_psk_client_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
    C.wolfSSL_CTX_set_psk_client_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_set_psk_server_tls13_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
    C.wolfSSL_CTX_set_psk_server_tls13_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_set_psk_client_tls13_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
    C.wolfSSL_CTX_set_psk_client_tls13_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_use_psk_identity_hint(ctx *C.struct_WOLFSSL_CTX, hint string) int {
    c_hint := C.CString(hint)
    defer C.free(unsafe.Pointer(c_hint))
    return int(C.wolfSSL_CTX_use_psk_identity_hint(ctx, c_hint))
}

func WolfSSL_CTX_load_verify_locations(ctx *C.struct_WOLFSSL_CTX, cert string,
                                       path []byte) int {
    cert_file := C.CString(cert)
    defer C.free(unsafe.Pointer(cert_file))
    /* TODO: HANDLE NON NIL PATH */
    return int(C.wolfSSL_CTX_load_verify_locations(ctx, cert_file,
               (*C.char)(unsafe.Pointer(nil))))
}

func WolfSSL_CTX_use_certificate_file(ctx *C.struct_WOLFSSL_CTX, cert string,
                                      format int) int {
    cert_file := C.CString(cert)
    defer C.free(unsafe.Pointer(cert_file))
    return int(C.wolfSSL_CTX_use_certificate_file(ctx, cert_file, C.int(format)))
}

func WolfSSL_CTX_use_PrivateKey_file(ctx *C.struct_WOLFSSL_CTX, key string,
                                     format int) int {
    key_file := C.CString(key)
    defer C.free(unsafe.Pointer(key_file))
    return int(C.wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, C.int(format)))
}

func WolfSSL_set_fd(ssl *C.struct_WOLFSSL, fd int) {
    C.wolfSSL_set_fd(ssl, C.int(fd))
}

func WolfSSL_accept(ssl *C.struct_WOLFSSL) int {
    return int(C.wolfSSL_accept(ssl))
}

func WolfSSL_read(ssl *C.struct_WOLFSSL, data []byte, sz uintptr) int {
    if sz == 0 { return 0 }
    if len(data) == 0 || sz > uintptr(len(data)) {
        return BAD_FUNC_ARG
    }
    return int(C.wolfSSL_read(ssl, unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_write(ssl *C.struct_WOLFSSL, data []byte, sz uintptr) int {
    if sz == 0 { return 0 }
    if len(data) == 0 || sz > uintptr(len(data)) {
        return BAD_FUNC_ARG
    }
    return int(C.wolfSSL_write(ssl, unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_get_error(ssl *C.struct_WOLFSSL, ret int) int {
    return int(C.wolfSSL_get_error(ssl, C.int(ret)))
}

// data parameter is unused; kept for API compatibility.
func WolfSSL_ERR_error_string(ret int, data []byte) string {
    var buf [C.WOLFSSL_MAX_ERROR_SZ]C.char
    return C.GoString(C.wolfSSL_ERR_error_string(C.ulong(ret), &buf[0]))
}

func WolfSSL_get_cipher_name(ssl *C.struct_WOLFSSL) string {
    return C.GoString(C.wolfSSL_get_cipher_name(ssl))
}

func WolfSSL_get_version(ssl *C.struct_WOLFSSL) string {
    return C.GoString(C.wolfSSL_get_version(ssl))
}

func WolfSSL_lib_version() string {
    return C.GoString(C.wolfSSL_lib_version())
}

func WolfSSL_Debugging_ON() {
    C.wolfSSL_Debugging_ON()
}

func WolfSSL_Debugging_OFF() {
    C.wolfSSL_Debugging_OFF()
}

/* Verification mode constants */
const SSL_VERIFY_NONE = 0
const SSL_VERIFY_PEER = 1
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2
const SSL_VERIFY_CLIENT_ONCE = 4

/* SNI type constant */
const WOLFSSL_SNI_HOST_NAME = 0

/* ALPN option constants */
const WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 1
const WOLFSSL_ALPN_FAILED_ON_MISMATCH = 2

func WolfSSLv23_client_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfSSLv23_client_method()
}

func WolfSSLv23_server_method() *C.struct_WOLFSSL_METHOD {
    return C.wolfSSLv23_server_method()
}

func WolfSSL_CTX_set_verify(ctx *C.struct_WOLFSSL_CTX, mode int) {
    C.wolfSSL_CTX_set_verify(ctx, C.int(mode), nil)
}

func WolfSSL_CTX_load_verify_buffer(ctx *C.struct_WOLFSSL_CTX, buf []byte,
                                     sz int, format int) int {
    if sz <= 0 || sz > len(buf) || len(buf) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_CTX_load_verify_buffer(ctx,
               (*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(format)))
}

func WolfSSL_CTX_use_certificate_buffer(ctx *C.struct_WOLFSSL_CTX, buf []byte,
                                         sz int, format int) int {
    if sz <= 0 || sz > len(buf) || len(buf) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_CTX_use_certificate_buffer(ctx,
               (*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(format)))
}


func WolfSSL_CTX_use_certificate_chain_buffer_format(ctx *C.struct_WOLFSSL_CTX, buf []byte,
                                         sz int, format int) int {
    if sz <= 0 || sz > len(buf) || len(buf) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,
               (*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(format)))
}


func WolfSSL_use_certificate_chain_buffer_format(ssl *C.struct_WOLFSSL, buf []byte,
                                         sz int, format int) int {
    if sz <= 0 || sz > len(buf) || len(buf) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_use_certificate_chain_buffer_format(ssl,
               (*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(format)))
}

func WolfSSL_CTX_use_PrivateKey_buffer(ctx *C.struct_WOLFSSL_CTX, buf []byte,
                                        sz int, format int) int {
    if sz <= 0 || sz > len(buf) || len(buf) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_CTX_use_PrivateKey_buffer(ctx,
               (*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(format)))
}

func WolfSSL_UseSNI(ssl *C.struct_WOLFSSL, sniType int, data []byte, size int) int {
    if size <= 0 || size > len(data) || len(data) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_UseSNI(ssl, C.uchar(sniType),
               unsafe.Pointer(&data[0]), C.ushort(size)))
}

func WolfSSL_CTX_UseSNI(ctx *C.struct_WOLFSSL_CTX, sniType int, data []byte, size int) int {
    if size <= 0 || size > len(data) || len(data) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_CTX_UseSNI(ctx, C.uchar(sniType),
               unsafe.Pointer(&data[0]), C.ushort(size)))
}

func WolfSSL_UseALPN(ssl *C.struct_WOLFSSL, protoList string, options int) int {
    c_list := C.CString(protoList)
    defer C.free(unsafe.Pointer(c_list))
    return int(C.wolfSSL_UseALPN(ssl, c_list, C.uint(len(protoList)), C.uchar(options)))
}

func WolfSSL_ALPN_GetProtocol(ssl *C.struct_WOLFSSL) (string, int) {
    var proto *C.char
    var size C.ushort
    ret := int(C.wolfSSL_ALPN_GetProtocol(ssl, &proto, &size))
    if ret != WOLFSSL_SUCCESS || proto == nil {
        return "", ret
    }
    return C.GoStringN(proto, C.int(size)), ret
}

func WolfSSL_ALPN_GetPeerProtocol(ssl *C.struct_WOLFSSL) ([]string, int) {
    var listC *C.char
    var sizeC C.ushort
    ret := int(C.wolfSSL_ALPN_GetPeerProtocol(ssl, &listC, &sizeC))
    if ret != WOLFSSL_SUCCESS || listC == nil {
        return nil, ret
    }
    // wolfSSL returns a NUL-terminated, comma-separated C string with
    // strlen() == sizeC. Build a Go []string, then free the C buffer
    // via wolfSSL's matching free helper (uses ssl->heap).
    s := C.GoStringN(listC, C.int(sizeC))
    C.wolfSSL_ALPN_FreePeerProtocol(ssl, &listC)
    if s == "" {
        return nil, WOLFSSL_SUCCESS
    }
    parts := make([]string, 0, 4)
    start := 0
    for i := 0; i <= len(s); i++ {
        if i == len(s) || s[i] == ',' {
            if i > start {
                parts = append(parts, s[start:i])
            }
            start = i + 1
        }
    }
    return parts, WOLFSSL_SUCCESS
}

func WolfSSL_get_peer_certificate(ssl *C.struct_WOLFSSL) *C.struct_WOLFSSL_X509 {
    return C.wolfSSL_get_peer_certificate(ssl)
}

func WolfSSL_get_peer_chain(ssl *C.struct_WOLFSSL) *C.WOLFSSL_X509_CHAIN {
    return C.wolfSSL_get_peer_chain(ssl)
}

func WolfSSL_get_chain_count(chain *C.WOLFSSL_X509_CHAIN) int {
    return int(C.wolfSSL_get_chain_count(chain))
}

func WolfSSL_get_chain_cert(chain *C.WOLFSSL_X509_CHAIN, idx int) []byte {
    length := int(C.wolfSSL_get_chain_length(chain, C.int(idx)))
    if length <= 0 { return nil }
    ptr := C.wolfSSL_get_chain_cert(chain, C.int(idx))
    if ptr == nil { return nil }
    return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}

func WolfSSL_get_chain_length(chain *C.WOLFSSL_X509_CHAIN, idx int) int {
    return int(C.wolfSSL_get_chain_length(chain, C.int(idx)))
}

/* Helper functions that create a WOLFSSL_CTX directly from a version-flexible
 * method, avoiding the need for callers to handle *C.struct_WOLFSSL_METHOD. */

func WolfSSL_CTX_new_v23_client() *WOLFSSL_CTX {
    return C.wolfSSL_CTX_new(C.wolfSSLv23_client_method())
}

func WolfSSL_CTX_new_v23_server() *WOLFSSL_CTX {
    return C.wolfSSL_CTX_new(C.wolfSSLv23_server_method())
}

func WolfSSL_CTX_new_TLSv1_2_client() *WOLFSSL_CTX {
    return C.wolfSSL_CTX_new(C.wolfTLSv1_2_client_method())
}

func WolfSSL_CTX_new_TLSv1_2_server() *WOLFSSL_CTX {
    return C.wolfSSL_CTX_new(C.wolfTLSv1_2_server_method())
}

func WolfSSL_CTX_new_TLSv1_3_client() *WOLFSSL_CTX {
    return C.wolfSSL_CTX_new(C.wolfTLSv1_3_client_method())
}

func WolfSSL_CTX_new_TLSv1_3_server() *WOLFSSL_CTX {
    return C.wolfSSL_CTX_new(C.wolfTLSv1_3_server_method())
}

// WolfSSL_get_peer_cert_chain_DER extracts the peer certificate chain from
// a completed TLS session as a slice of DER-encoded certificates. The first
// element is the leaf certificate. Returns nil if no peer certificates are
// available.
//
// All returned byte slices are Go-owned copies. The internal wolfSSL pointers
// are only borrowed during this call and are not retained.
//
// Chain path (SESSION_CERTS): wolfSSL_get_peer_chain returns a pointer into
// ssl->session->chain (borrowed, not a copy). wolfSSL_get_chain_cert returns
// chain->certs[idx].buffer (also borrowed). We copy immediately via C.GoBytes.
//
// Leaf fallback: wolfSSL_get_peer_certificate returns a dup (caller-owned,
// must free). wolfSSL_X509_get_der returns an internal pointer into the
// X509 — no allocation, valid until the X509 is freed. We copy via
// C.GoBytes before releasing the X509.
func WolfSSL_get_peer_cert_chain_DER(ssl *WOLFSSL) [][]byte {
    var certs [][]byte

    // Try SESSION_CERTS chain first.
    chain := C.wolfSSL_get_peer_chain(ssl)
    if chain != nil {
        count := int(C.wolfSSL_get_chain_count(chain))
        for i := 0; i < count; i++ {
            length := int(C.wolfSSL_get_chain_length(chain, C.int(i)))
            if length <= 0 { continue }
            // wolfSSL_get_chain_cert returns an internal pointer — copy now.
            ptr := C.wolfSSL_get_chain_cert(chain, C.int(i))
            if ptr == nil { continue }
            certs = append(certs, C.GoBytes(unsafe.Pointer(ptr), C.int(length)))
        }
        if len(certs) > 0 {
            return certs
        }
    }

    // Fallback: leaf certificate only.
    // wolfSSL_get_peer_certificate returns a dup — we own it and must free.
    peerX509 := C.wolfSSL_get_peer_certificate(ssl)
    if peerX509 == nil {
        return nil
    }
    defer C.wolfSSL_X509_free(peerX509)

    // wolfSSL_X509_get_der returns an internal pointer (no copy, no free).
    // Preferred over wolfSSL_i2d_X509: not gated on OPENSSL_EXTRA, so it's
    // available wherever wolfSSL_get_peer_certificate is.
    var outSz C.int
    derPtr := C.wolfSSL_X509_get_der(peerX509, &outSz)
    if derPtr == nil || outSz <= 0 {
        return nil
    }
    return [][]byte{C.GoBytes(unsafe.Pointer(derPtr), outSz)}
}

/* Protocol version constants matching wolfSSL's internal values. */
const (
    WOLFSSL_TLSV1   = 1
    WOLFSSL_TLSV1_1 = 2
    WOLFSSL_TLSV1_2 = 3
    WOLFSSL_TLSV1_3 = 4
)

func WolfSSL_CTX_set_min_proto_version(ctx *WOLFSSL_CTX, ver int) int {
    return int(C.wolfSSL_CTX_set_min_proto_version(ctx, C.int(ver)))
}

func WolfSSL_CTX_set_max_proto_version(ctx *WOLFSSL_CTX, ver int) int {
    return int(C.wolfSSL_CTX_set_max_proto_version(ctx, C.int(ver)))
}


func WolfSSL_SNI_GetServerName(ssl *WOLFSSL) string {
    var buf [256]C.char
    n := C.ssl_SNI_GetRequest(ssl, &buf[0], 256)
    if n <= 0 { return "" }
    return C.GoStringN(&buf[0], n)
}


func WolfSSL_use_certificate_buffer(ssl *WOLFSSL, buf []byte, sz int, format int) int {
    if sz <= 0 || sz > len(buf) || len(buf) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_use_certificate_buffer(ssl,
               (*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(format)))
}


func WolfSSL_use_PrivateKey_buffer(ssl *WOLFSSL, buf []byte, sz int, format int) int {
    if sz <= 0 || sz > len(buf) || len(buf) == 0 { return BAD_FUNC_ARG }
    return int(C.wolfSSL_use_PrivateKey_buffer(ssl,
               (*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(format)))
}

