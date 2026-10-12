/* aes_handles.go
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
	"errors"
	"fmt"
	"sync"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// AesGcmAEAD implements crypto/cipher.AEAD using wolfCrypt AES-256-GCM.
// Create one with NewAesGcmAEAD and call Zero when it is no longer needed.
type AesGcmAEAD struct {
	st *aesGcmState
}

// aesGcmState is shared by copies of an AesGcmAEAD so Zero reaches them all.
type aesGcmState struct {
	mu     sync.RWMutex
	key    [wolfSSL.AES_256_KEY_SIZE]byte
	zeroed bool
}

// errAesGcmAuth is returned from Open for any decrypt/verify failure
// (including too-short ciphertext) so callers cannot distinguish those
// cases — matches crypto/cipher's GCM error contract.
var errAesGcmAuth = errors.New("wolfSSL: AES-GCM authentication failed")

// NewAesGcmAEAD returns an AesGcmAEAD keyed with a 32-byte AES-256 key.
func NewAesGcmAEAD(key [wolfSSL.AES_256_KEY_SIZE]byte) *AesGcmAEAD {
	return &AesGcmAEAD{st: &aesGcmState{key: key}}
}

// Zero wipes the key held by a (best effort: the Go runtime may already have
// copied it). Zero waits for in-flight Seal and Open calls; afterwards Seal
// panics and Open fails.
func (a *AesGcmAEAD) Zero() {
	st := a.st
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	zeroBytes(st.key[:])
	st.zeroed = true
}

// use read-locks the key state for one operation, or returns nil if the
// AEAD was not built by NewAesGcmAEAD or has been zeroed.
func (a *AesGcmAEAD) use() *aesGcmState {
	st := a.st
	if st == nil {
		return nil
	}
	st.mu.RLock()
	if st.zeroed {
		st.mu.RUnlock()
		return nil
	}
	if testHookAcquired != nil {
		testHookAcquired()
	}
	return st
}

func (a *AesGcmAEAD) NonceSize() int { return wolfSSL.GCM_NONCE_MID_SZ }
func (a *AesGcmAEAD) Overhead() int  { return wolfSSL.AES_BLOCK_SIZE }

// Seal encrypts and authenticates plaintext, appending the result to dst.
// The ciphertext and tag are concatenated: dst || ct || tag. Panics on
// programming errors (wrong nonce length, wolfCrypt init/encrypt failure)
// to match crypto/cipher.AEAD's contract.
func (a *AesGcmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic("wolfSSL/handles: incorrect nonce length given to AEAD")
	}
	st := a.use()
	if st == nil {
		panic("wolfSSL/handles: AEAD used after Zero or without NewAesGcmAEAD")
	}
	defer st.mu.RUnlock()
	aes := wolfSSL.Wc_AesAllocAligned()
	if aes == nil {
		panic("wolfSSL/handles: Wc_AesAllocAligned returned nil")
	}
	defer wolfSSL.Wc_AesFreeAllocAligned(aes)
	if ret := wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/handles: wc_AesInit failed: %d", ret))
	}
	defer wolfSSL.Wc_AesFree(aes)
	if ret := wolfSSL.Wc_AesGcmSetKey(aes, st.key[:], wolfSSL.AES_256_KEY_SIZE); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/handles: wc_AesGcmSetKey failed: %d", ret))
	}

	ct := make([]byte, len(plaintext))
	var tag [wolfSSL.AES_BLOCK_SIZE]byte
	if ret := wolfSSL.Wc_AesGcmEncrypt(aes, ct, plaintext, nonce, tag[:], additionalData); ret != 0 {
		panic(fmt.Sprintf("wolfSSL/handles: wc_AesGcmEncrypt failed: %d", ret))
	}

	out := append(dst, ct...)
	out = append(out, tag[:]...)
	return out
}

// Open decrypts and verifies ciphertext (which must include the appended
// tag), appending the plaintext to dst. Panics on wrong nonce length;
// returns a single authentication-failure error for any decrypt/verify
// failure (including too-short ciphertext or wc_* setup errors) to avoid
// leaking distinguishable failure modes.
func (a *AesGcmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("wolfSSL/handles: incorrect nonce length given to AEAD")
	}
	if len(ciphertext) < a.Overhead() {
		return nil, errAesGcmAuth
	}
	st := a.use()
	if st == nil {
		return nil, errAesGcmAuth
	}
	defer st.mu.RUnlock()
	aes := wolfSSL.Wc_AesAllocAligned()
	if aes == nil {
		return nil, errAesGcmAuth
	}
	defer wolfSSL.Wc_AesFreeAllocAligned(aes)
	if ret := wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		return nil, errAesGcmAuth
	}
	defer wolfSSL.Wc_AesFree(aes)
	if ret := wolfSSL.Wc_AesGcmSetKey(aes, st.key[:], wolfSSL.AES_256_KEY_SIZE); ret != 0 {
		return nil, errAesGcmAuth
	}

	ctLen := len(ciphertext) - a.Overhead()
	ct := ciphertext[:ctLen]
	tag := ciphertext[ctLen:]

	plaintext := make([]byte, ctLen)
	if ret := wolfSSL.Wc_AesGcmDecrypt(aes, plaintext, ct, nonce, tag, additionalData); ret != 0 {
		zeroBytes(plaintext)
		return nil, errAesGcmAuth
	}
	return append(dst, plaintext...), nil
}
