/* conn_lifecycle_test.go
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

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const lifecycleTimeout = 5 * time.Second

// notifyConn reports each transport Read made while armed.
type notifyConn struct {
	net.Conn
	armed   int32
	entered chan struct{}
}

func newNotifyConn(c net.Conn) *notifyConn {
	return &notifyConn{Conn: c, entered: make(chan struct{}, 1)}
}

func (n *notifyConn) Read(b []byte) (int, error) {
	if atomic.LoadInt32(&n.armed) == 1 {
		select {
		case n.entered <- struct{}{}:
		default:
		}
	}
	return n.Conn.Read(b)
}

func TestWriteProceedsWhileReadWaits(t *testing.T) {
	var nc *notifyConn
	cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
		nc = newNotifyConn(c)
		return nc
	})
	defer cleanup()

	atomic.StoreInt32(&nc.armed, 1)
	reply := make([]byte, 4)
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(cli, reply)
		readDone <- err
	}()
	select {
	case <-nc.entered:
	case <-time.After(lifecycleTimeout):
		t.Fatal("client Read never reached the transport")
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := cli.Write([]byte("ping"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("client write: %v", err)
		}
	case <-time.After(lifecycleTimeout):
		t.Fatal("Write blocked behind a Read waiting for input")
	}

	got := make([]byte, 4)
	if _, err := io.ReadFull(srv, got); err != nil || string(got) != "ping" {
		t.Fatalf("server read %q: %v", got, err)
	}
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	select {
	case err := <-readDone:
		if err != nil || string(reply) != "pong" {
			t.Fatalf("client read %q: %v", reply, err)
		}
	case <-time.After(lifecycleTimeout):
		t.Fatal("client Read did not complete")
	}
}

// panicConn panics from Read or Write once the matching flag is set.
type panicConn struct {
	net.Conn
	readPanics  int32
	writePanics int32
}

func (p *panicConn) Read(b []byte) (int, error) {
	switch atomic.LoadInt32(&p.readPanics) {
	case 1:
		panic("transport read failure")
	case 2:
		p.Conn.Read(b)
		panic("transport read failure after partial input")
	}
	return p.Conn.Read(b)
}

func (p *panicConn) Write(b []byte) (int, error) {
	switch atomic.LoadInt32(&p.writePanics) {
	case 1:
		panic("transport write failure")
	case 2:
		panic(nil)
	case 3:
		p.Conn.Write(b[:len(b)/2])
		panic("transport write failure after partial output")
	}
	return p.Conn.Write(b)
}

// callNoPanic runs f and fails the test if a panic escapes it.
func callNoPanic(t *testing.T, f func() error) error {
	t.Helper()
	var err error
	var escaped interface{}
	func() {
		defer func() { escaped = recover() }()
		err = f()
	}()
	if escaped != nil {
		t.Fatalf("panic escaped through wolfSSL: %v", escaped)
	}
	return err
}

func TestCallbackPanicBecomesError(t *testing.T) {
	t.Run("transport read", func(t *testing.T) {
		cConn, sConn := net.Pipe()
		defer sConn.Close()
		go io.Copy(io.Discard, sConn)
		pc := &panicConn{Conn: cConn, readPanics: 1}
		cli := Client(pc, &Config{ServerName: "localhost", InsecureSkipVerify: true})
		defer cli.Close()
		if err := callNoPanic(t, cli.Handshake); err == nil {
			t.Fatal("handshake succeeded over a panicking transport")
		}
	})

	t.Run("transport write", func(t *testing.T) {
		var pc *panicConn
		cli, _, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
			pc = &panicConn{Conn: c}
			return pc
		})
		defer cleanup()
		atomic.StoreInt32(&pc.writePanics, 1)
		defer atomic.StoreInt32(&pc.writePanics, 0)
		err := callNoPanic(t, func() error {
			_, err := cli.Write([]byte("data"))
			return err
		})
		if err == nil {
			t.Fatal("write succeeded over a panicking transport")
		}
	})

	t.Run("transport write nil panic", func(t *testing.T) {
		var pc *panicConn
		cli, _, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
			pc = &panicConn{Conn: c}
			return pc
		})
		defer cleanup()
		atomic.StoreInt32(&pc.writePanics, 2)
		defer atomic.StoreInt32(&pc.writePanics, 0)
		done := make(chan error, 1)
		go func() {
			_, err := cli.Write([]byte("data"))
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("write succeeded over a panicking transport")
			}
		case <-time.After(lifecycleTimeout):
			t.Fatal("Write did not fail after the transport panicked")
		}
	})

	t.Run("transport write after partial output", func(t *testing.T) {
		var pc *panicConn
		cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
			pc = &panicConn{Conn: c}
			return pc
		})
		defer cleanup()
		// Drain post-handshake messages so closing the transport is a clean FIN.
		if _, err := srv.Write([]byte("x")); err != nil {
			t.Fatalf("server write: %v", err)
		}
		cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		if _, err := io.ReadFull(cli, make([]byte, 1)); err != nil {
			t.Fatalf("client read: %v", err)
		}

		msg := make([]byte, 100)
		atomic.StoreInt32(&pc.writePanics, 3)
		defer atomic.StoreInt32(&pc.writePanics, 0)
		err := callNoPanic(t, func() error {
			_, err := cli.Write(msg)
			return err
		})
		if err == nil {
			t.Fatal("write succeeded over a panicking transport")
		}
		atomic.StoreInt32(&pc.writePanics, 0)
		if _, err := cli.Write(msg); err == nil {
			t.Fatal("Write succeeded after the transport panicked mid-record")
		}
		srv.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		_, err = srv.Read(make([]byte, 16))
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			t.Fatalf("peer saw %v, want the transport closed after the partial record", err)
		}
	})

	t.Run("transport read after partial input", func(t *testing.T) {
		var pc *panicConn
		cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
			pc = &panicConn{Conn: c}
			return pc
		})
		defer cleanup()
		// Drain post-handshake messages so closing the transport is a clean FIN.
		if _, err := srv.Write([]byte("x")); err != nil {
			t.Fatalf("server write: %v", err)
		}
		cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		if _, err := io.ReadFull(cli, make([]byte, 1)); err != nil {
			t.Fatalf("client read: %v", err)
		}

		atomic.StoreInt32(&pc.readPanics, 2)
		defer atomic.StoreInt32(&pc.readPanics, 0)
		if _, err := srv.Write([]byte("data")); err != nil {
			t.Fatalf("server write: %v", err)
		}
		err := callNoPanic(t, func() error {
			_, err := cli.Read(make([]byte, 16))
			return err
		})
		if err == nil {
			t.Fatal("read succeeded over a panicking transport")
		}
		srv.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		_, err = srv.Read(make([]byte, 16))
		if ne, ok := err.(net.Error); err == nil || (ok && ne.Timeout()) {
			t.Fatalf("peer saw %v, want the transport closed after the lost input", err)
		}
	})

	t.Run("GetCertificate", func(t *testing.T) {
		certPEM := loadFile(t, certPath("server-cert.pem"))
		keyPEM := loadFile(t, certPath("server-key.pem"))
		var called int32
		serverConfig := &Config{
			Certificates: []Certificate{{CertPEM: certPEM, KeyPEM: keyPEM}},
			GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
				atomic.StoreInt32(&called, 1)
				panic("certificate lookup failure")
			},
		}
		cConn, sConn := tcpPair(t)
		cli := Client(cConn, &Config{ServerName: "localhost", InsecureSkipVerify: true})
		defer cli.Close()
		go cli.Handshake()
		srv := Server(sConn, serverConfig)
		defer srv.Close()
		err := callNoPanic(t, srv.Handshake)
		if atomic.LoadInt32(&called) == 0 {
			t.Skip("wolfSSL built without WOLFSSL_CERT_SETUP_CB; GetCertificate not invoked")
		}
		if err == nil {
			t.Fatal("handshake succeeded after GetCertificate panicked")
		}
	})
}

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-accepted
	if server == nil {
		client.Close()
		t.Fatal("accept failed")
	}
	return client, server
}

// timeoutError is a net.Error that reports a deadline expiry.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyWriteFailure(t *testing.T) {
	var timeout error = timeoutError{}
	cases := []struct {
		name         string
		errCode      int
		transportErr error
		dead, retry  bool
	}{
		{"timeout with record pending", sslErrorWantWrite, timeout, true, false},
		{"wrapped timeout", sslErrorWantWrite, fmt.Errorf("w: %w", timeout), true, false},
		{"transport stall", sslErrorWantWrite, nil, false, true},
		{"wolfSSL wants input", sslErrorWantRead, nil, false, false},
		{"wolfSSL wants input after a timeout", sslErrorWantRead, timeout, false, false},
	}
	for _, tc := range cases {
		dead, retry := classifyWriteFailure(tc.errCode, tc.transportErr)
		if dead != tc.dead || retry != tc.retry {
			t.Errorf("%s: dead=%v retry=%v, want dead=%v retry=%v", tc.name, dead, retry, tc.dead, tc.retry)
		}
	}
}

// stallOnceConn returns (0, nil) from the first Write made while armed.
type stallOnceConn struct {
	net.Conn
	armed int32
}

func (s *stallOnceConn) Write(b []byte) (int, error) {
	if atomic.CompareAndSwapInt32(&s.armed, 1, 0) {
		return 0, nil
	}
	return s.Conn.Write(b)
}

func TestWriteStallWithoutTimeoutIsRetried(t *testing.T) {
	var sc *stallOnceConn
	cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
		sc = &stallOnceConn{Conn: c}
		return sc
	})
	defer cleanup()

	atomic.StoreInt32(&sc.armed, 1)
	if _, err := cli.Write([]byte("first")); err != nil {
		t.Fatalf("Write after a transport stall: %v", err)
	}
	if _, err := cli.Write([]byte("second")); err != nil {
		t.Fatalf("later Write: %v", err)
	}
	srv.SetReadDeadline(time.Now().Add(lifecycleTimeout))
	got := make([]byte, len("firstsecond"))
	if _, err := io.ReadFull(srv, got); err != nil || string(got) != "firstsecond" {
		t.Fatalf("server read %q: %v", got, err)
	}
}

// emptyConn returns (0, nil) from every Read and Write made while armed.
type emptyConn struct {
	net.Conn
	reads, writes int32
}

func (e *emptyConn) Read(b []byte) (int, error) {
	if atomic.LoadInt32(&e.reads) == 1 {
		return 0, nil
	}
	return e.Conn.Read(b)
}

func (e *emptyConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&e.writes) == 1 {
		return 0, nil
	}
	return e.Conn.Write(b)
}

func TestWriteWithoutProgressFails(t *testing.T) {
	var ec *emptyConn
	cli, _, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
		ec = &emptyConn{Conn: c}
		return ec
	})
	defer cleanup()

	atomic.StoreInt32(&ec.writes, 1)
	writeDone := make(chan error, 1)
	go func() {
		_, err := cli.Write([]byte("stuck"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("Write err = %v, want io.ErrNoProgress", err)
		}
	case <-time.After(lifecycleTimeout):
		t.Fatal("Write kept retrying a transport that makes no progress")
	}
	if _, err := cli.Write([]byte("later")); err == nil {
		t.Fatal("Write succeeded after a possibly half-sent record")
	}
}

func TestReadWithoutProgressFails(t *testing.T) {
	var ec *emptyConn
	cli, _, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
		ec = &emptyConn{Conn: c}
		return ec
	})
	defer cleanup()
	if cli.sslMu == nil {
		t.Skip("write dup splits the session; no shared input pump")
	}

	atomic.StoreInt32(&ec.reads, 1)
	readDone := make(chan error, 1)
	go func() {
		_, err := cli.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("Read err = %v, want io.ErrNoProgress", err)
		}
	case <-time.After(lifecycleTimeout):
		t.Fatal("Read kept retrying a transport that makes no progress")
	}
}

// readCounter counts transport Reads and signals each one.
type readCounter struct {
	net.Conn
	reads   int32
	entered chan struct{}
}

func (r *readCounter) Read(b []byte) (int, error) {
	atomic.AddInt32(&r.reads, 1)
	select {
	case r.entered <- struct{}{}:
	default:
	}
	return r.Conn.Read(b)
}

func TestSharedSessionInputPumpTakesTurns(t *testing.T) {
	var rcnt *readCounter
	cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
		rcnt = &readCounter{Conn: c, entered: make(chan struct{}, 1)}
		return rcnt
	})
	defer cleanup()
	if cli.sslMu == nil {
		t.Skip("write dup splits the session; no shared input pump")
	}
	rc := cli.conn.(*recordingConn)
	cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))

	// Drain post-handshake messages, then park a Read in the pump.
	if _, err := srv.Write([]byte("x")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if _, err := io.ReadFull(cli, make([]byte, 1)); err != nil {
		t.Fatalf("client read: %v", err)
	}
	for len(rcnt.entered) > 0 {
		<-rcnt.entered
	}
	gen := rc.fillCount()
	readDone := make(chan string, 1)
	go func() {
		buf := make([]byte, 4)
		n, _ := io.ReadFull(cli, buf)
		readDone <- string(buf[:n])
	}()
	select {
	case <-rcnt.entered:
	case <-time.After(lifecycleTimeout):
		t.Fatal("Read never waited on the transport")
	}
	readsBefore := atomic.LoadInt32(&rcnt.reads)

	// A writer needing input queues behind the parked Read instead of
	// reading the transport itself, and returns once that input lands.
	pumped := make(chan error, 1)
	go func() { pumped <- cli.pumpInput(rc, gen) }()
	if _, err := srv.Write([]byte("data")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	select {
	case err := <-pumped:
		if err != nil {
			t.Fatalf("pump: %v", err)
		}
	case <-time.After(lifecycleTimeout):
		t.Fatal("writer pump did not return after input arrived")
	}
	select {
	case got := <-readDone:
		if got != "data" {
			t.Fatalf("Read got %q", got)
		}
	case <-time.After(lifecycleTimeout):
		t.Fatal("Read did not complete")
	}
	if extra := atomic.LoadInt32(&rcnt.reads) - readsBefore; extra != 0 {
		t.Fatalf("writer pump read the transport %d extra times", extra)
	}
}

func TestSendTimeoutClosesWritesInsideWolfSSLCall(t *testing.T) {
	cli, _, cleanup := setupPair(t)
	defer cleanup()
	rc := cli.conn.(*recordingConn)

	cli.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	chunk := make([]byte, 16384)
	failed := false
	for i := 0; i < 4096 && !failed; i++ {
		n, _ := cli.writeRecord(chunk)
		failed = n <= 0
	}
	if !failed {
		t.Fatal("write deadline never fired")
	}
	// No Write bookkeeping has run yet; a concurrent Read must already be
	// unable to flush the half-sent record.
	if !rc.writeClosed() {
		t.Fatal("transport timeout left writes open after WolfSSL_write returned")
	}
}

func TestReadAfterWriteTimeoutSendsNothing(t *testing.T) {
	cli, srv, cleanup := setupPair(t)
	defer cleanup()

	// Consume post-handshake messages so closing the client does not reset
	// the connection and discard what the server has yet to read.
	if _, err := srv.Write([]byte("x")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
	if _, err := io.ReadFull(cli, make([]byte, 1)); err != nil {
		t.Fatalf("client read: %v", err)
	}

	const chunk = 16384
	var want []byte
	var err error
	cli.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	for i := 0; i < 2048 && err == nil; i++ {
		msg := bytes.Repeat([]byte{byte(i)}, chunk)
		var n int
		n, err = cli.Write(msg)
		want = append(want, msg[:n]...)
	}
	if err == nil {
		t.Fatal("write deadline never fired")
	}
	cli.SetWriteDeadline(time.Time{})

	// A KeyUpdate request makes the client's Read want to send a reply.
	srv.muWrite.Lock()
	ret := sslRequestKeyUpdate(srv.sslWrite)
	srv.muWrite.Unlock()
	if ret != 1 {
		t.Skipf("key update unavailable (%d)", ret)
	}
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}

	type result struct {
		got   []byte
		err   error
		extra int
	}
	done := make(chan result, 1)
	go func() {
		srv.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		got := make([]byte, len(want))
		_, err := io.ReadFull(srv, got)
		extra := 0
		if err == nil {
			extra, _ = srv.Read(make([]byte, 1))
		}
		done <- result{got, err, extra}
	}()
	cli.Read(make([]byte, 4))
	cli.Close()

	r := <-done
	if r.err != nil {
		t.Fatalf("server read of the reported bytes: %v", r.err)
	}
	if !bytes.Equal(r.got, want) {
		t.Fatal("server stream differs from the bytes Write reported as written")
	}
	if r.extra != 0 {
		t.Fatal("server received plaintext that Write reported as unsent")
	}
}

func TestLargeWriteTimeoutReportsDeliveredBytes(t *testing.T) {
	cli, srv, cleanup := setupPair(t)
	defer cleanup()

	// Consume post-handshake messages so closing the client does not reset
	// the connection and discard what the server has yet to read.
	if _, err := srv.Write([]byte("x")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
	if _, err := io.ReadFull(cli, make([]byte, 1)); err != nil {
		t.Fatalf("client read: %v", err)
	}

	big := make([]byte, 64<<20)
	for i := range big {
		big[i] = byte(i / 16384)
	}
	cli.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	n, err := cli.Write(big)
	if err == nil {
		t.Fatal("write deadline never fired")
	}
	if n == 0 || n == len(big) {
		t.Fatalf("Write reported %d of %d bytes; want a partial count", n, len(big))
	}
	cli.Close()

	srv.SetReadDeadline(time.Now().Add(lifecycleTimeout))
	got := make([]byte, n)
	if m, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("server read %d of %d reported bytes: %v", m, n, err)
	}
	if !bytes.Equal(got, big[:n]) {
		t.Fatal("server stream differs from the bytes Write reported as written")
	}
	if m, err := srv.Read(make([]byte, 1)); m != 0 || err == nil {
		t.Fatalf("server received bytes beyond the %d Write reported (m=%d err=%v)", n, m, err)
	}
}

// wrapErrConn wraps every transport error with %w, as net.Conn decorators do.
type wrapErrConn struct{ net.Conn }

func (w wrapErrConn) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if err != nil {
		err = fmt.Errorf("wrapped read: %w", err)
	}
	return n, err
}

func (w wrapErrConn) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	if err != nil {
		err = fmt.Errorf("wrapped write: %w", err)
	}
	return n, err
}

func TestWrappedWriteTimeoutIsRecognized(t *testing.T) {
	cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn { return wrapErrConn{c} })
	defer cleanup()

	cli.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	var err error
	msg := make([]byte, 16384)
	for i := 0; i < 2048 && err == nil; i++ {
		_, err = cli.Write(msg)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("wrapped write deadline error is not a timeout: %v", err)
	}
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
	reply := make([]byte, 4)
	if _, err := io.ReadFull(cli, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("client read after wrapped write timeout %q: %v", reply, err)
	}
}

func TestWriteTimeoutKeepsStreamConsistent(t *testing.T) {
	cli, srv, cleanup := setupPair(t)
	defer cleanup()

	const chunk = 16384
	var want []byte
	var err error
	cli.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	for i := 0; i < 2048; i++ {
		msg := bytes.Repeat([]byte{byte(i)}, chunk)
		var n int
		n, err = cli.Write(msg)
		want = append(want, msg[:n]...)
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("write deadline never fired")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("write deadline error is not a timeout: %v", err)
	}
	cli.SetWriteDeadline(time.Time{})

	if n, err := cli.Write([]byte("different payload")); err == nil || n != 0 {
		t.Fatalf("Write after a timed-out record: n=%d err=%v, want the timeout again", n, err)
	}

	// The read side is unaffected by the write timeout.
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
	reply := make([]byte, 4)
	if _, err := io.ReadFull(cli, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("client read after write timeout %q: %v", reply, err)
	}

	// The peer gets exactly the bytes Write reported, then no clean close.
	cli.Close()
	srv.SetReadDeadline(time.Now().Add(lifecycleTimeout))
	got := make([]byte, len(want))
	if n, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("server read %d of %d reported bytes: %v", n, len(want), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("server stream differs from the bytes Write reported as written")
	}
	if n, err := srv.Read(make([]byte, 1)); n != 0 || err == nil || err == io.EOF {
		t.Fatalf("after the reported bytes: n=%d err=%v, want a truncation error", n, err)
	}
}

var errAfterData = errors.New("transport error after data")

// errAfterRecordConn, once armed, stages the next TLS record from the
// transport and returns errAfterData together with its final bytes.
type errAfterRecordConn struct {
	net.Conn
	armed  int32
	staged []byte
}

func (e *errAfterRecordConn) Read(b []byte) (int, error) {
	if len(e.staged) == 0 {
		if atomic.LoadInt32(&e.armed) == 0 {
			return e.Conn.Read(b)
		}
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(e.Conn, hdr); err != nil {
			return 0, err
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(e.Conn, body); err != nil {
			return 0, err
		}
		e.staged = append(hdr, body...)
		atomic.StoreInt32(&e.armed, 0)
	}
	n := copy(b, e.staged)
	e.staged = e.staged[n:]
	if len(e.staged) == 0 {
		return n, errAfterData
	}
	return n, nil
}

func TestReadErrorComesFromCurrentCall(t *testing.T) {
	var ec *errAfterRecordConn
	cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn {
		ec = &errAfterRecordConn{Conn: c}
		return ec
	})
	defer cleanup()
	cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))

	// Drain post-handshake messages so the armed record is the application data.
	buf := make([]byte, 3)
	if _, err := srv.Write([]byte("one")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if _, err := io.ReadFull(cli, buf); err != nil || string(buf) != "one" {
		t.Fatalf("client read %q: %v", buf, err)
	}

	atomic.StoreInt32(&ec.armed, 1)
	if _, err := srv.Write([]byte("two")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	n, err := cli.Read(buf)
	if err != nil || string(buf[:n]) != "two" {
		t.Fatalf("Read of data delivered with an error: %q, %v", buf[:n], err)
	}
	if _, err := cli.Read(buf); !errors.Is(err, errAfterData) {
		t.Fatalf("next Read: got %v, want the transport error returned with the data", err)
	}
}

func TestReadDistinguishesTruncationFromCloseNotify(t *testing.T) {
	t.Run("transport closed without close_notify", func(t *testing.T) {
		cli, srv, cleanup := setupPair(t)
		defer cleanup()
		srv.NetConn().Close()
		cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		if _, err := cli.Read(make([]byte, 16)); err != io.ErrUnexpectedEOF {
			t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("wrapped transport EOF", func(t *testing.T) {
		cli, srv, cleanup := setupPairWith(t, func(c net.Conn) net.Conn { return wrapErrConn{c} })
		defer cleanup()
		srv.NetConn().Close()
		cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		if _, err := cli.Read(make([]byte, 16)); err != io.ErrUnexpectedEOF {
			t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("close_notify", func(t *testing.T) {
		cli, srv, cleanup := setupPair(t)
		defer cleanup()
		srv.Close()
		cli.SetReadDeadline(time.Now().Add(lifecycleTimeout))
		if _, err := cli.Read(make([]byte, 16)); err != io.EOF {
			t.Fatalf("got %v, want io.EOF", err)
		}
	})
}
