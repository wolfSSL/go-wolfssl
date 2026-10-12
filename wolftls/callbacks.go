/* callbacks.go
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

package wolftls

// /* cgo directives for this package live in conn.go. */
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
// #include <wolfssl/wolfio.h>
// #include <stdint.h>
// #include <string.h>
//
// /* Forward declarations — implemented in Go via //export. */
// extern int wolftlsIORecv(void* ssl, char* buf, int sz, void* ctx);
// extern int wolftlsIOSend(void* ssl, char* buf, int sz, void* ctx);
// extern int wolftlsSNICallback(void* ssl, int connID);
// extern int wolftlsCertSetupCallback(void* ssl, int connID);
//
// /* I/O callback trampolines: wolfSSL invokes these for every TLS
//  * record read/write. They forward into Go via the //export functions. */
// static int ioRecvTrampoline(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
//     return wolftlsIORecv((void*)ssl, buf, sz, ctx);
// }
// static int ioSendTrampoline(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
//     return wolftlsIOSend((void*)ssl, buf, sz, ctx);
// }
//
// static inline int wolftls_update_keys(WOLFSSL* ssl) {
// #ifdef WOLFSSL_TLS13
//     return wolfSSL_update_keys(ssl);
// #else
//     (void)ssl;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* SNI callback trampoline. exArg carries the Go connID; the Go
//  * callback's return is mapped to wolfSSL's switch/return convention:
//  *   0 -> success (default case)
//  *   non-zero -> fatal_return + alert_fatal. */
// #ifdef HAVE_SNI
// static int sniTrampoline(WOLFSSL* ssl, int* ret, void* exArg) {
//     int connID = (int)(intptr_t)exArg;
//     int rc = wolftlsSNICallback((void*)ssl, connID);
//     if (rc != 0) {
//         *ret = alert_fatal;
//         return fatal_return;
//     }
//     return 0;
// }
// #endif
//
// /* CertSetup trampoline. Returns 1=success, 0=error per wolfSSL contract. */
// #ifdef WOLFSSL_CERT_SETUP_CB
// static int certSetupTrampoline(WOLFSSL* ssl, void* arg) {
//     int connID = (int)(intptr_t)arg;
//     return wolftlsCertSetupCallback((void*)ssl, connID);
// }
// #endif
//
// /* Helpers that take the trampoline addresses without exposing Go to
//  * the C function-pointer types (which cgo can't always represent). */
// static inline void wolftls_set_io_recv(WOLFSSL_CTX* ctx) {
//     wolfSSL_CTX_SetIORecv(ctx, ioRecvTrampoline);
// }
// static inline void wolftls_set_io_send(WOLFSSL_CTX* ctx) {
//     wolfSSL_CTX_SetIOSend(ctx, ioSendTrampoline);
// }
// #ifdef HAVE_SNI
// static inline void wolftls_set_sni_cb(WOLFSSL_CTX* ctx, int connID) {
//     wolfSSL_CTX_set_servername_callback(ctx, (CallbackSniRecv)sniTrampoline);
//     wolfSSL_CTX_set_servername_arg(ctx, (void*)(intptr_t)connID);
// }
// #endif
// #ifdef WOLFSSL_CERT_SETUP_CB
// static inline void wolftls_set_cert_cb(WOLFSSL_CTX* ctx, int connID) {
//     wolfSSL_CTX_set_cert_cb(ctx, certSetupTrampoline,
//                              (void*)(intptr_t)connID);
// }
// #else
// /* Stub for vanilla wolfSSL builds without WOLFSSL_CERT_SETUP_CB.
//  * wolftls.Conn's per-connection GetCertificate callback is unavailable
//  * in this build mode; ctxSetCertSetupCallback becomes a no-op. */
// static inline void wolftls_set_cert_cb(WOLFSSL_CTX* ctx, int connID) {
//     (void)ctx; (void)connID;
// }
// #endif
import "C"

import (
	"errors"
	"io"
	"net"
	"sync"
	"unsafe"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// I/O callback error codes returned to wolfSSL. Mirror the values in
// wolfssl/internal.h so wolfSSL's read/write loop interprets them
// correctly.
const (
	cbioErrGeneral   = -1
	cbioErrWantRead  = -2
	cbioErrWantWrite = -2
	cbioErrConnRst   = -3
	cbioErrISR       = -4
	cbioErrConnClose = -5
	cbioErrTimeout   = -6
)

const (
	sslErrorWantRead   = int(C.WOLFSSL_ERROR_WANT_READ)
	sslErrorWantWrite  = int(C.WOLFSSL_ERROR_WANT_WRITE)
	sslErrorZeroReturn = int(C.WOLFSSL_ERROR_ZERO_RETURN)
)

// ------------------------------------------------------------------
// I/O callback registry: route wolfSSL record I/O through a Go net.Conn
// ------------------------------------------------------------------

type ioConn struct {
	conn net.Conn
}

var (
	ioMu     sync.Mutex
	ioConns  = make(map[int]*ioConn)
	ioNextID int
)

func registerIOConn(conn net.Conn) int {
	ioMu.Lock()
	defer ioMu.Unlock()
	ioNextID++
	id := ioNextID
	ioConns[id] = &ioConn{conn: conn}
	return id
}

func unregisterIOConn(id int) {
	ioMu.Lock()
	defer ioMu.Unlock()
	delete(ioConns, id)
}

func getIOConn(id int) *ioConn {
	ioMu.Lock()
	defer ioMu.Unlock()
	return ioConns[id]
}

// A Go panic must not unwind through wolfSSL's C frames, so each exported
// callback converts one into the callback's error return.

// transportPanicError replaces a panic from the caller's net.Conn.
type transportPanicError struct{}

func (transportPanicError) Error() string { return "wolftls: transport panicked" }

// guardTransport runs one transport Read or Write. If it panics, the
// transport is closed, since it may have moved bytes wolfSSL never saw.
func guardTransport(c net.Conn, op func() (int, error)) (n int, err error) {
	panicked := true
	defer func() {
		if panicked {
			recover()
			closeQuietly(c)
			n, err = 0, transportPanicError{}
		}
	}()
	n, err = op()
	panicked = false
	return n, err
}

func closeQuietly(c net.Conn) {
	defer func() { recover() }()
	c.Close()
}

//export wolftlsIORecv
func wolftlsIORecv(sslPtr unsafe.Pointer, buf *C.char, sz C.int, ctx unsafe.Pointer) (ret C.int) {
	ret = C.int(cbioErrGeneral)
	defer func() { recover() }()
	if sz < 0 {
		return C.int(cbioErrGeneral)
	}
	connID := int(uintptr(ctx))
	ic := getIOConn(connID)
	if ic == nil {
		return C.int(cbioErrGeneral)
	}

	goBuf := make([]byte, int(sz))
	n, buffered := 0, false
	if rc, ok := ic.conn.(*recordingConn); ok {
		n, buffered = rc.takeBuffered(goBuf)
	}
	var err error
	if !buffered {
		n, err = guardTransport(ic.conn, func() (int, error) { return ic.conn.Read(goBuf) })
	}
	if n > 0 {
		C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&goBuf[0]), C.size_t(n))
		return C.int(n)
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return C.int(cbioErrConnClose)
		}
		// Hitting the user set deadline for the read has no implication
		// for the underlying TCP connection. Loop with WANT_READ.
		if isTimeout(err) {
			return C.int(cbioErrWantRead)
		}
		return C.int(cbioErrGeneral)
	}
	return C.int(cbioErrWantRead)
}

// isTimeout reports whether err, or any error it wraps, is a net.Error timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

//export wolftlsIOSend
func wolftlsIOSend(sslPtr unsafe.Pointer, buf *C.char, sz C.int, ctx unsafe.Pointer) (ret C.int) {
	ret = C.int(cbioErrGeneral)
	defer func() { recover() }()
	if sz < 0 {
		return C.int(cbioErrGeneral)
	}
	connID := int(uintptr(ctx))
	ic := getIOConn(connID)
	if ic == nil {
		return C.int(cbioErrGeneral)
	}

	// Nothing more may reach the peer once a record was left half-sent.
	if rc, ok := ic.conn.(*recordingConn); ok && rc.writeClosed() {
		return C.int(cbioErrWantWrite)
	}
	goBuf := C.GoBytes(unsafe.Pointer(buf), sz)
	n, err := guardTransport(ic.conn, func() (int, error) { return ic.conn.Write(goBuf) })
	if n > 0 {
		return C.int(n)
	}
	if err != nil {
		if isTimeout(err) {
			// Close writes while wolfSSL still holds the session, so no other
			// caller can flush the half-sent record.
			if rc, ok := ic.conn.(*recordingConn); ok {
				rc.closeWrites(err)
			}
			return C.int(cbioErrWantWrite)
		}
		return C.int(cbioErrConnClose)
	}
	return C.int(cbioErrWantWrite)
}

// sslMaxPlaintext returns the most plaintext one record carries on a
// handshaken ssl.
func sslMaxPlaintext(ssl *wolfSSL.WOLFSSL) int {
	n := int(C.wolfSSL_GetMaxOutputSize((*C.WOLFSSL)(unsafe.Pointer(ssl))))
	if n <= 0 || n > 16384 {
		return 16384
	}
	return n
}

// sslRequestKeyUpdate sends a TLS 1.3 KeyUpdate that asks the peer to
// respond; it returns WOLFSSL_SUCCESS or a negative error.
func sslRequestKeyUpdate(ssl *wolfSSL.WOLFSSL) int {
	return int(C.wolftls_update_keys((*C.WOLFSSL)(unsafe.Pointer(ssl))))
}

// ctxSetIOCallbacks installs the I/O trampolines on a WOLFSSL_CTX.
// Every wolftls.Conn calls this on its CTX.
func ctxSetIOCallbacks(ctx *wolfSSL.WOLFSSL_CTX) {
	C.wolftls_set_io_recv((*C.WOLFSSL_CTX)(unsafe.Pointer(ctx)))
	C.wolftls_set_io_send((*C.WOLFSSL_CTX)(unsafe.Pointer(ctx)))
}

// sslSetIOCtx wires the per-conn ioConn ID into a specific SSL session
// so wolfSSL's read/write callbacks recover the right net.Conn.
func sslSetIOCtx(ssl *wolfSSL.WOLFSSL, connID int) {
	ptr := unsafe.Pointer(uintptr(connID))
	C.wolfSSL_SetIOReadCtx((*C.WOLFSSL)(unsafe.Pointer(ssl)), ptr)
	C.wolfSSL_SetIOWriteCtx((*C.WOLFSSL)(unsafe.Pointer(ssl)), ptr)
}

// ------------------------------------------------------------------
// SNI callback registry
// ------------------------------------------------------------------

// sniCallbackFunc is the per-conn SNI callback signature.
// It receives the WOLFSSL pointer and the server name from the
// ClientHello and should load the right cert/key into the session.
// Return 0 on success, non-zero to fail the handshake.
type sniCallbackFunc func(ssl *wolfSSL.WOLFSSL, serverName string) int

var (
	sniMu        sync.Mutex
	sniCallbacks = make(map[int]sniCallbackFunc)
	sniNextID    int
)

func registerSNICallback(cb sniCallbackFunc) int {
	sniMu.Lock()
	defer sniMu.Unlock()
	sniNextID++
	id := sniNextID
	sniCallbacks[id] = cb
	return id
}

func unregisterSNICallback(id int) {
	sniMu.Lock()
	defer sniMu.Unlock()
	delete(sniCallbacks, id)
}

//export wolftlsSNICallback
func wolftlsSNICallback(sslPtr unsafe.Pointer, connID C.int) (ret C.int) {
	ret = 1
	defer func() { recover() }()
	ssl := (*wolfSSL.WOLFSSL)(sslPtr)
	serverName := wolfSSL.WolfSSL_SNI_GetServerName(ssl)

	sniMu.Lock()
	cb, ok := sniCallbacks[int(connID)]
	sniMu.Unlock()

	if !ok {
		return 0 // no callback registered; default cert path
	}
	return C.int(cb(ssl, serverName))
}

// ctxSetSNICallback installs the SNI trampoline on ctx, with connID as
// the opaque arg the trampoline will look up at handshake time.
func ctxSetSNICallback(ctx *wolfSSL.WOLFSSL_CTX, connID int) {
	C.wolftls_set_sni_cb((*C.WOLFSSL_CTX)(unsafe.Pointer(ctx)), C.int(connID))
}

// ------------------------------------------------------------------
// CertSetup callback registry
// ------------------------------------------------------------------
//
// wolfSSL's CertSetupCallback fires after ClientHello parsing but
// before the cert/key availability check. Inside it, SNI and ALPN
// extensions are already populated, so callers can read them via
// wolfSSL_SNI_GetRequest / wolfSSL_ALPN_GetPeerProtocol to drive
// per-connection cert selection.
//
// Return code semantics:
//   1  -> success (cert installed; continue handshake)
//   0  -> error (sends fatal alert)
//  <0  -> WANT_X509_LOOKUP (suspends handshake; not used here)

// certSetupCallbackFunc installs cert + key on the SSL via the wolfSSL
// per-session helpers. Return 1 on success, 0 on error.
type certSetupCallbackFunc func(ssl *wolfSSL.WOLFSSL) int

var (
	certCbMu        sync.Mutex
	certCbCallbacks = make(map[int]certSetupCallbackFunc)
	certCbNextID    int
)

func registerCertSetupCallback(cb certSetupCallbackFunc) int {
	certCbMu.Lock()
	defer certCbMu.Unlock()
	certCbNextID++
	id := certCbNextID
	certCbCallbacks[id] = cb
	return id
}

func unregisterCertSetupCallback(id int) {
	certCbMu.Lock()
	defer certCbMu.Unlock()
	delete(certCbCallbacks, id)
}

//export wolftlsCertSetupCallback
func wolftlsCertSetupCallback(sslPtr unsafe.Pointer, connID C.int) (ret C.int) {
	ret = 0
	defer func() { recover() }()
	ssl := (*wolfSSL.WOLFSSL)(sslPtr)
	certCbMu.Lock()
	cb, ok := certCbCallbacks[int(connID)]
	certCbMu.Unlock()
	if !ok {
		return 1 // no callback registered; use whatever wolfSSL has
	}
	return C.int(cb(ssl))
}

// ctxSetCertSetupCallback installs the CertSetup trampoline on ctx with
// connID as the opaque arg the trampoline will look up.
func ctxSetCertSetupCallback(ctx *wolfSSL.WOLFSSL_CTX, connID int) {
	C.wolftls_set_cert_cb((*C.WOLFSSL_CTX)(unsafe.Pointer(ctx)), C.int(connID))
}
