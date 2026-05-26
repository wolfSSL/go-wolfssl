/* listener.go
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
	"net"
)

// listener wraps a net.Listener and upgrades accepted connections to TLS.
type listener struct {
	inner  net.Listener
	config *Config
}

// NewListener wraps inner such that each accepted connection is upgraded
// to a TLS server connection using the provided config.
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &listener{
		inner:  inner,
		config: config,
	}
}

// Accept waits for and returns the next TLS connection to the listener.
func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return Server(conn, l.config), nil
}

// Close closes the underlying listener.
func (l *listener) Close() error {
	return l.inner.Close()
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.inner.Addr()
}
