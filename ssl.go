package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
import "C"
import (
    "unsafe"
)

const SSL_FILETYPE_PEM = 1
const WOLFSSL_SUCCESS  = 1


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

func WolfSSL_new(ctx *C.struct_WOLFSSL_CTX) *C.struct_WOLFSSL {
    return C.wolfSSL_new(ctx)
}

func WolfSSL_connect(ssl *C.struct_WOLFSSL) C.int {
    return C.wolfSSL_connect(ssl)
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

func WolfSSL_CTX_load_verify_locations(ctx *C.struct_WOLFSSL_CTX, cert string, path []byte) C.int {
    cert_file := C.CString(cert)
    defer C.free(unsafe.Pointer(cert_file))
    /* TODO: HANDLE NON NIL PATH */
    return C.wolfSSL_CTX_load_verify_locations(ctx, cert_file, (*C.char)(unsafe.Pointer(nil)))
}

func WolfSSL_CTX_use_certificate_file(ctx *C.struct_WOLFSSL_CTX, cert string, format int) C.int {
    cert_file := C.CString(cert)
    defer C.free(unsafe.Pointer(cert_file))
    return C.wolfSSL_CTX_use_certificate_file(ctx, cert_file, C.int(format))
}

func WolfSSL_CTX_use_PrivateKey_file(ctx *C.struct_WOLFSSL_CTX, key string, format int) C.int {
    key_file := C.CString(key)
    defer C.free(unsafe.Pointer(key_file))
    return C.wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, C.int(format))
}

func WolfSSL_set_fd(ssl *C.struct_WOLFSSL, fd int) {
    C.wolfSSL_set_fd(ssl, C.int(fd))
}

func WolfSSL_accept(ssl *C.struct_WOLFSSL) C.int {
    return C.wolfSSL_accept(ssl)
}

func WolfSSL_read(ssl *C.struct_WOLFSSL, data []byte, sz uintptr) C.int {
    return C.wolfSSL_read(ssl, unsafe.Pointer(&data[0]), C.int(sz))
}

func WolfSSL_write(ssl *C.struct_WOLFSSL, data []byte, sz uintptr) C.int {
    return C.wolfSSL_write(ssl, unsafe.Pointer(&data[0]), C.int(sz))
}

