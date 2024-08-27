/* ssl.go
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
// #include <wolfssl/ssl.h>
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
import "C"
import (
    "unsafe"
)

const SSL_FILETYPE_PEM = 1
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
    return int(C.wolfSSL_read(ssl, unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_write(ssl *C.struct_WOLFSSL, data []byte, sz uintptr) int {
    return int(C.wolfSSL_write(ssl, unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_get_error(ssl *C.struct_WOLFSSL, ret int) int {
    return int(C.wolfSSL_get_error(ssl, C.int(ret)))
}

func WolfSSL_ERR_error_string(ret int, data []byte) string {
    return C.GoString(C.wolfSSL_ERR_error_string(C.ulong(ret), (*C.char)(unsafe.Pointer(&data[0]))))
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
