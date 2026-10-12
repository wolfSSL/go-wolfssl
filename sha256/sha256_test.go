/* sha256_test.go
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

package sha256

import (
	"bytes"
	stdsha256 "crypto/sha256"
	"strings"
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

func TestDigestWriteMatchesStdlib(t *testing.T) {
	h := New()
	msg := []byte("abc")
	n, err := h.Write(msg)
	if n != len(msg) || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(msg))
	}
	want := stdsha256.Sum256(msg)
	if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
		t.Fatalf("Sum = %x, want %x", got, want)
	}
}

func TestDigestWriteFailurePanics(t *testing.T) {
	orig := sha256Update
	sha256Update = func(sha *wolfSSL.Wc_Sha256, data []byte, sz int) int {
		return wolfSSL.BAD_FUNC_ARG
	}
	defer func() { sha256Update = orig }()

	d := New().(*digest)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Write did not panic on a wolfCrypt update failure")
		}
		if s, ok := r.(string); !ok || !strings.Contains(s, "Wc_Sha256Update") {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	n, err := d.Write([]byte("abc"))
	t.Errorf("Write returned (%d, %v) instead of panicking", n, err)
}
