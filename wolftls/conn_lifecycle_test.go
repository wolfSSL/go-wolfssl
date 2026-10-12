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
