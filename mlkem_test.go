/* mlkem_test.go
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
    "testing"
)

// testMlKemLevel runs the full keygen → encap → decap round-trip for one level.
func testMlKemLevel(t *testing.T, level MlKemLevel, pubSz, privSz, ctSz, ssSz int) {
    t.Helper()

    pubA, privA, err := MlKemGenerateKey(level)
    if err != nil {
        t.Fatalf("MlKemGenerateKey: %v", err)
    }
    if len(pubA) != pubSz {
        t.Errorf("public key length: got %d, want %d", len(pubA), pubSz)
    }
    if len(privA) != privSz {
        t.Errorf("private key length: got %d, want %d", len(privA), privSz)
    }

    ct, ssEnc, err := MlKemEncapsulate(level, pubA)
    if err != nil {
        t.Fatalf("MlKemEncapsulate: %v", err)
    }
    if len(ct) != ctSz {
        t.Errorf("ciphertext length: got %d, want %d", len(ct), ctSz)
    }
    if len(ssEnc) != ssSz {
        t.Errorf("encap shared secret length: got %d, want %d", len(ssEnc), ssSz)
    }

    ssDec, err := MlKemDecapsulate(level, privA, ct)
    if err != nil {
        t.Fatalf("MlKemDecapsulate: %v", err)
    }
    if len(ssDec) != ssSz {
        t.Errorf("decap shared secret length: got %d, want %d", len(ssDec), ssSz)
    }

    if !bytes.Equal(ssEnc, ssDec) {
        t.Error("shared secrets do not match after round-trip")
    }
}

func TestMlKem512(t *testing.T) {
    testMlKemLevel(t, MlKemLevel512,
        MLKEM_512_PUB_SIZE, MLKEM_512_PRIV_SIZE,
        MLKEM_512_CIPHERTEXT_SIZE, MLKEM_512_SHARED_SIZE)
}

func TestMlKem768(t *testing.T) {
    testMlKemLevel(t, MlKemLevel768,
        MLKEM_768_PUB_SIZE, MLKEM_768_PRIV_SIZE,
        MLKEM_768_CIPHERTEXT_SIZE, MLKEM_768_SHARED_SIZE)
}

func TestMlKem1024(t *testing.T) {
    testMlKemLevel(t, MlKemLevel1024,
        MLKEM_1024_PUB_SIZE, MLKEM_1024_PRIV_SIZE,
        MLKEM_1024_CIPHERTEXT_SIZE, MLKEM_1024_SHARED_SIZE)
}

// TestMlKemWrongKey: encapsulate to key A, decapsulate with key B.
// Under ML-KEM implicit rejection semantics the decapsulation always
// "succeeds" (returns no error) but produces a different shared secret.
func TestMlKemWrongKey(t *testing.T) {
    level := MlKemLevel768

    pubA, _, err := MlKemGenerateKey(level)
    if err != nil {
        t.Fatalf("keygen A: %v", err)
    }
    _, privB, err := MlKemGenerateKey(level)
    if err != nil {
        t.Fatalf("keygen B: %v", err)
    }

    ct, ssA, err := MlKemEncapsulate(level, pubA)
    if err != nil {
        t.Fatalf("encapsulate: %v", err)
    }

    ssB, err := MlKemDecapsulate(level, privB, ct)
    if err != nil {
        // Some wolfSSL builds may return an error; that is also acceptable.
        t.Logf("MlKemDecapsulate with wrong key returned error (acceptable): %v", err)
        return
    }

    if bytes.Equal(ssA, ssB) {
        t.Error("shared secrets should differ when decapsulating with the wrong key")
    }
}
