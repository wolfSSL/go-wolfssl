/* hash_test.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package wolfSSL

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Known-answer tests against RFC/FIPS published vectors.
func TestSha256Hash_KnownAnswers(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string // hex digest
	}{
		{"empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"long", "The quick brown fox jumps over the lazy dog",
			"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := make([]byte, WC_SHA256_DIGEST_SIZE)
			input := []byte(tc.input)
			ret := Wc_Sha256Hash(input, len(input), out)
			skipIfNotCompiledIn(t, ret, "SHA-256")
			if ret != 0 {
				t.Fatalf("Wc_Sha256Hash returned %d", ret)
			}
			got := hex.EncodeToString(out)
			if got != tc.want {
				t.Fatalf("digest mismatch:\n got:  %s\n want: %s", got, tc.want)
			}
		})
	}
}

func TestSha384Hash_EmptyInput(t *testing.T) {
	out := make([]byte, WC_SHA384_DIGEST_SIZE)
	ret := Wc_Sha384Hash(nil, 0, out)
	if ret == notCompiledIn {
		t.Skip("SHA-384 not compiled in")
	}
	if ret != 0 {
		t.Fatalf("Wc_Sha384Hash returned %d", ret)
	}
	want := "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("digest mismatch: got %s, want %s", got, want)
	}
}

func TestSha512Hash_EmptyInput(t *testing.T) {
	out := make([]byte, WC_SHA512_DIGEST_SIZE)
	ret := Wc_Sha512Hash(nil, 0, out)
	if ret == notCompiledIn {
		t.Skip("SHA-512 not compiled in")
	}
	if ret != 0 {
		t.Fatalf("Wc_Sha512Hash returned %d", ret)
	}
	want := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("digest mismatch: got %s, want %s", got, want)
	}
}

// Boundary: output buffer too small must return error, not panic / corrupt memory.
func TestSha256Hash_ShortOutputBuffer(t *testing.T) {
	out := make([]byte, WC_SHA256_DIGEST_SIZE-1)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("short output should error, not panic: %v", r)
		}
	}()
	if ret := Wc_Sha256Hash([]byte("data"), 4, out); ret == 0 {
		t.Fatal("expected error on undersized output buffer")
	}
}

// Boundary: inputSz larger than slice must return error, not let wc read past Go memory.
func TestSha256Hash_OversizedInputSz(t *testing.T) {
	in := []byte("hi")
	out := make([]byte, WC_SHA256_DIGEST_SIZE)
	if ret := Wc_Sha256Hash(in, 1<<20, out); ret == 0 {
		t.Fatal("expected error on inputSz > len(input)")
	}
}

// Streaming Sha256 should match one-shot.
func TestSha256_Streaming_MatchesOneShot(t *testing.T) {
	chunks := []string{"part one", " part two", " final part"}
	full := []byte("part one part two final part")

	oneShot := make([]byte, WC_SHA256_DIGEST_SIZE)
	ret := Wc_Sha256Hash(full, len(full), oneShot)
	skipIfNotCompiledIn(t, ret, "SHA-256")
	if ret != 0 {
		t.Fatalf("one-shot Sha256Hash returned %d", ret)
	}

	var ctx Wc_Sha256
	ret = Wc_InitSha256_ex(&ctx, nil, INVALID_DEVID)
	skipIfNotCompiledIn(t, ret, "SHA-256")
	if ret != 0 {
		t.Fatalf("InitSha256_ex returned %d", ret)
	}
	t.Cleanup(func() { Wc_Sha256Free(&ctx) })
	for _, c := range chunks {
		b := []byte(c)
		if ret := Wc_Sha256Update(&ctx, b, len(b)); ret != 0 {
			t.Fatalf("Sha256Update returned %d", ret)
		}
	}
	streaming := make([]byte, WC_SHA256_DIGEST_SIZE)
	if ret := Wc_Sha256Final(&ctx, streaming); ret != 0 {
		t.Fatalf("Sha256Final returned %d", ret)
	}

	if !bytes.Equal(oneShot, streaming) {
		t.Fatalf("streaming != one-shot:\n  one:  %x\n  strm: %x", oneShot, streaming)
	}
}
