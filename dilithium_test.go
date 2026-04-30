//go:build dilithium

/* dilithium_test.go
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

func testMlDsaLevel(t *testing.T, level MlDsaLevel) {
    t.Helper()

    pub, priv, err := MlDsaGenerateKey(level)
    if err != nil {
        t.Fatalf("MlDsaGenerateKey: %v", err)
    }

    msg := []byte("wolfSSL ML-DSA test message")

    sig, err := MlDsaSign(level, priv, msg)
    if err != nil {
        t.Fatalf("MlDsaSign: %v", err)
    }

    // Valid signature should verify.
    ok, err := MlDsaVerify(level, pub, msg, sig)
    if err != nil {
        t.Fatalf("MlDsaVerify (valid): %v", err)
    }
    if !ok {
        t.Error("expected valid signature to verify successfully")
    }

    // Tampered message should not verify.
    tampered := append([]byte(nil), msg...)
    tampered[0] ^= 0xff
    ok, err = MlDsaVerify(level, pub, tampered, sig)
    if err != nil {
        t.Logf("MlDsaVerify (tampered msg) returned error: %v", err)
    }
    if ok {
        t.Error("expected tampered message to fail verification")
    }

    // Tampered signature should not verify.
    badSig := append([]byte(nil), sig...)
    badSig[0] ^= 0xff
    ok, err = MlDsaVerify(level, pub, msg, badSig)
    if err != nil {
        t.Logf("MlDsaVerify (bad sig) returned error: %v", err)
    }
    if ok {
        t.Error("expected tampered signature to fail verification")
    }

    // Signature from a different key should not verify.
    pub2, _, err := MlDsaGenerateKey(level)
    if err != nil {
        t.Fatalf("MlDsaGenerateKey (key2): %v", err)
    }
    ok, err = MlDsaVerify(level, pub2, msg, sig)
    if err != nil {
        t.Logf("MlDsaVerify (wrong key) returned error: %v", err)
    }
    if ok {
        t.Error("expected signature to fail with a different public key")
    }

    // Size assertions.
    pubSz, privSz, sigSz, _ := mldsaSizes(level)
    if !bytes.Equal(pub[:pubSz], pub) {
        t.Errorf("public key length mismatch: got %d, want %d", len(pub), pubSz)
    }
    if !bytes.Equal(priv[:privSz], priv) {
        t.Errorf("private key length mismatch: got %d, want %d", len(priv), privSz)
    }
    if len(sig) > sigSz {
        t.Errorf("signature length %d exceeds max %d", len(sig), sigSz)
    }
}

func TestMlDsa44(t *testing.T) { testMlDsaLevel(t, MlDsaLevel44) }
func TestMlDsa65(t *testing.T) { testMlDsaLevel(t, MlDsaLevel65) }
func TestMlDsa87(t *testing.T) { testMlDsaLevel(t, MlDsaLevel87) }
