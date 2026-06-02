/* rsa_handles.go
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

package handles

import (
    "bytes"
    "errors"
    "fmt"
    "runtime"

    wolfSSL "github.com/wolfssl/go-wolfssl"
)

// RsaKey is a wolfCrypt RSA public-key handle. The zero value is not
// usable; obtain one via NewEmptyRsaKey or ImportRsaPublicRaw. Callers
// must Free the key when done; freeing twice is safe.
//
// This handle currently only carries enough state for verify
// operations. Sign/decrypt callers will need an RNG attached, mirroring
// EccKey.hasRng — out of scope until needed.
type RsaKey struct {
    raw  wolfSSL.RsaKey
    init bool // wc_InitRsaKey has run
    live bool // additionally, key material is populated
}

// NewEmptyRsaKey returns an RsaKey with wc_InitRsaKey called but no key
// material populated. Higher-level helpers fill in key bytes via
// wc_RsaPublicKeyDecodeRaw / wc_RsaPublicKeyDecode and then call
// MarkLive. Free releases the key regardless of whether MarkLive was
// called, so it is safe to defer immediately after construction.
func NewEmptyRsaKey() (*RsaKey, error) {
    k := &RsaKey{}
    if ret := wolfSSL.Wc_InitRsaKey(&k.raw); ret != 0 {
        return nil, fmt.Errorf("wolfCrypt: wc_InitRsaKey: %d", ret)
    }
    k.init = true
    runtime.SetFinalizer(k, (*RsaKey).Free)
    return k, nil
}

// MarkLive flags the key as fully populated.
func (k *RsaKey) MarkLive() { k.live = true }

// IsLive reports whether the key has key material loaded and is not yet
// freed.
func (k *RsaKey) IsLive() bool { return k != nil && k.live }

// Free releases the wolfCrypt key. Safe to call multiple times.
func (k *RsaKey) Free() {
    if k == nil || !k.init {
        return
    }
    wolfSSL.Wc_FreeRsaKey(&k.raw)
    k.init = false
    k.live = false
    runtime.SetFinalizer(k, nil)
}

// Raw returns the underlying wolfCrypt RsaKey for direct use with
// low-level Wc_* APIs. The returned pointer is invalid after Free.
func (k *RsaKey) Raw() *wolfSSL.RsaKey { return &k.raw }

// ImportRsaPublicRaw imports an RSA public key from the raw modulus n
// and public exponent e (big-endian byte slices, e.g. as carried in a
// JWK or in *rsa.PublicKey.{N.Bytes(),E}).
func ImportRsaPublicRaw(n, e []byte) (*RsaKey, error) {
    if len(n) == 0 || len(e) == 0 {
        return nil, errors.New("handles: ImportRsaPublicRaw: empty n or e")
    }
    k, err := NewEmptyRsaKey()
    if err != nil {
        return nil, err
    }
    if ret := wolfSSL.Wc_RsaPublicKeyDecodeRaw(n, e, k.Raw()); ret != 0 {
        k.Free()
        return nil, fmt.Errorf("wolfCrypt: wc_RsaPublicKeyDecodeRaw: %d", ret)
    }
    k.MarkLive()
    return k, nil
}

// checkDigestLen ensures the supplied digest matches the output size of
// hashType
func checkDigestLen(op string, hashType int, digest []byte) error {
    sz := wolfSSL.Wc_HashGetDigestSize(hashType)
    if sz <= 0 {
        return fmt.Errorf("handles: %s: unsupported hashType %d", op, hashType)
    }
    if len(digest) != sz {
        return fmt.Errorf("handles: %s: digest length %d does not match hashType %d (expected %d)",
            op, len(digest), hashType, sz)
    }
    return nil
}

// RsaVerifyPSS verifies an RSASSA-PSS signature using
// MGF1 with the same hash family as hashType. saltLen is fixed at
// hashLen.
func RsaVerifyPSS(pub *RsaKey, hashType int, digest, sig []byte) error {
    if !pub.IsLive() {
        return errors.New("handles: RsaVerifyPSS: key is not live")
    }
    if len(digest) == 0 || len(sig) == 0 {
        return errors.New("handles: RsaVerifyPSS: empty digest or sig")
    }
    if err := checkDigestLen("RsaVerifyPSS", hashType, digest); err != nil {
        return err
    }
    var mgf int
    switch hashType {
    case wolfSSL.WC_HASH_TYPE_SHA256:
        mgf = wolfSSL.WC_MGF1SHA256
    case wolfSSL.WC_HASH_TYPE_SHA384:
        mgf = wolfSSL.WC_MGF1SHA384
    case wolfSSL.WC_HASH_TYPE_SHA512:
        mgf = wolfSSL.WC_MGF1SHA512
    default:
        return fmt.Errorf("handles: RsaVerifyPSS: unsupported hashType %d", hashType)
    }
    out := make([]byte, len(sig))
    ret := wolfSSL.Wc_RsaPSS_VerifyCheck(sig, out, digest, hashType, mgf, pub.Raw())
    if ret < 0 {
        return fmt.Errorf("wolfCrypt: wc_RsaPSS_VerifyCheck: %d", ret)
    }
    return nil
}

// RsaVerifyPKCS1v15 verifies an RSASSA-PKCS1-v1_5 signature
func RsaVerifyPKCS1v15(pub *RsaKey, hashType int, digest, sig []byte) error {
    if !pub.IsLive() {
        return errors.New("handles: RsaVerifyPKCS1v15: key is not live")
    }
    if len(digest) == 0 || len(sig) == 0 {
        return errors.New("handles: RsaVerifyPKCS1v15: empty digest or sig")
    }
    if err := checkDigestLen("RsaVerifyPKCS1v15", hashType, digest); err != nil {
        return err
    }
    hashOID := wolfSSL.Wc_HashGetOID(hashType)
    if hashOID < 0 {
        return fmt.Errorf("handles: wc_HashGetOID(%d): %d", hashType, hashOID)
    }
    encoded := make([]byte, wolfSSL.MAX_ENCODED_SIG_SZ)
    n := wolfSSL.Wc_EncodeSignature(encoded, digest, hashOID)
    if n <= 0 {
        return fmt.Errorf("wolfCrypt: wc_EncodeSignature: %d", n)
    }
    recovered := make([]byte, len(sig))
    ret := wolfSSL.Wc_RsaSSL_Verify(sig, recovered, pub.Raw())
    if ret < 0 {
        return fmt.Errorf("wolfCrypt: wc_RsaSSL_Verify: %d", ret)
    }
    if !bytes.Equal(recovered[:ret], encoded[:n]) {
        return errors.New("handles: RsaVerifyPKCS1v15: signature mismatch")
    }
    return nil
}
