/* tls.go
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
	"context"
	"net"
	"sync"
)

var initOnce sync.Once

// ensureInit initializes the wolfSSL library exactly once.
func ensureInit() {
	initOnce.Do(func() {
		wolfSSLInit()
	})
}

// Client returns a new TLS client-side connection wrapping conn.
// The handshake is deferred until the first Read or Write, or an
// explicit call to Handshake.
func Client(conn net.Conn, config *Config) *Conn {
	ensureInit()
	return newConn(conn, config, true)
}

// Server returns a new TLS server-side connection wrapping conn.
// The handshake is deferred until the first Read or Write, or an
// explicit call to Handshake.
func Server(conn net.Conn, config *Config) *Conn {
	ensureInit()
	return newConn(conn, config, false)
}

// Dial connects to the given network address using net.Dial and then
// initiates a TLS handshake, returning the resulting TLS connection.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// DialWithDialer connects to the given network address using dialer.Dial
// and then initiates a TLS handshake.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	cfg := config
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg = cfg.Clone()
		cfg.ServerName = host
	}

	tlsConn := Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// Dialer dials TLS connections using an underlying net.Dialer and a Config.
type Dialer struct {
	NetDialer *net.Dialer
	Config    *Config
}

// DialContext connects to the given network address and initiates a TLS
// handshake, respecting the provided context for cancellation.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := d.NetDialer
	if dialer == nil {
		dialer = new(net.Dialer)
	}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	cfg := d.Config
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg = cfg.Clone()
		cfg.ServerName = host
	}

	tlsConn := Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}
