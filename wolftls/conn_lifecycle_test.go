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
