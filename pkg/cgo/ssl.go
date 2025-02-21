// Package cgo provides CGo bindings for wolfSSL
package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

static int wolfSSL_Init_ex() {
    return wolfSSL_Init();
}

static void wolfSSL_Cleanup_ex() {
    wolfSSL_Cleanup();
}
*/
import "C"
import (
    "runtime"
    "sync"
)

var (
    initOnce sync.Once
    cleanupOnce sync.Once
)

func init() {
    initOnce.Do(func() {
        if ret := C.wolfSSL_Init_ex(); ret != C.SSL_SUCCESS {
            panic("wolfSSL_Init failed")
        }
        runtime.SetFinalizer(&cleanupOnce, func(_ *sync.Once) {
            cleanupOnce.Do(func() {
                C.wolfSSL_Cleanup_ex()
            })
        })
    })
}
