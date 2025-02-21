// Package cgo provides CGo bindings for wolfSSL
#ifndef _WOLFSSL_CGO_SSL_H_
#define _WOLFSSL_CGO_SSL_H_

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

// Helper functions for X509 operations
WOLFSSL_X509* d2i_X509_wrapper(const unsigned char* input, long length) {
    const unsigned char* ptr = input;
    return wolfSSL_d2i_X509(NULL, &ptr, length);
}

int SSL_SUCCESS_wrapper() {
    return SSL_SUCCESS;
}

#endif /* _WOLFSSL_CGO_SSL_H_ */
