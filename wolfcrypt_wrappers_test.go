package wolfSSL

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
)

const notCompiledE = -174

func newTestRNG(t *testing.T) *WC_RNG {
	t.Helper()
	rng := Wc_RNG_New()
	if rng == nil {
		t.Skip("RNG not available")
	}
	return rng
}

func TestEccNegatePrivateRejectsKeyWithoutCurve(t *testing.T) {
	key := new(Ecc_key)
	if ret := Wc_ecc_init(key); ret == notCompiledE {
		t.Skip("ECC not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer Wc_ecc_free(key)
	ret := Wc_ecc_negate_private(key)
	if ret == notCompiledE {
		t.Skip("ECC negate not compiled")
	}
	if ret != BAD_FUNC_ARG {
		t.Fatalf("negate on key without curve: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestEccNegatePrivateRequiresPrivateKey(t *testing.T) {
	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	priv := new(Ecc_key)
	if ret := Wc_ecc_init(priv); ret == notCompiledE {
		t.Skip("ECC not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer Wc_ecc_free(priv)
	if ret := Wc_ecc_make_key(rng, 32, priv); ret == notCompiledE {
		t.Skip("ECC not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_ecc_make_key: %d", ret)
	}
	ret := Wc_ecc_negate_private(priv)
	if ret == notCompiledE {
		t.Skip("ECC negate not compiled")
	}
	if ret != 0 {
		t.Fatalf("negate on private key: got %d, want 0", ret)
	}

	pubDer := make([]byte, 128)
	pubLen := len(pubDer)
	if ret := Wc_ecc_export_x963_ex(priv, pubDer, &pubLen, 0); ret != 0 {
		t.Fatalf("export x963: %d", ret)
	}
	pub := new(Ecc_key)
	if ret := Wc_ecc_init(pub); ret == notCompiledE {
		t.Skip("ECC not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer Wc_ecc_free(pub)
	if ret := Wc_ecc_import_x963_ex(pubDer, pubLen, pub, ECC_SECP256R1); ret != 0 {
		t.Fatalf("import x963: %d", ret)
	}
	if ret := Wc_ecc_negate_private(pub); ret != BAD_FUNC_ARG {
		t.Fatalf("negate on public-only key: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestEncodeSignatureSha512(t *testing.T) {
	oid := Wc_HashGetOID(WC_HASH_TYPE_SHA512)
	if oid < 0 {
		t.Skipf("Wc_HashGetOID: %d", oid)
	}
	digest := make([]byte, WC_SHA512_DIGEST_SIZE)
	out := make([]byte, 256)
	n := Wc_EncodeSignature(out, digest, oid)
	if n != 19+WC_SHA512_DIGEST_SIZE {
		t.Fatalf("SHA-512 DigestInfo: got %d, want %d", n, 19+WC_SHA512_DIGEST_SIZE)
	}
}

func TestEncodeSignatureShortOutput(t *testing.T) {
	oid := Wc_HashGetOID(WC_HASH_TYPE_SHA256)
	if oid < 0 {
		t.Skipf("Wc_HashGetOID: %d", oid)
	}
	digest := make([]byte, WC_SHA256_DIGEST_SIZE)
	full := make([]byte, 256)
	n := Wc_EncodeSignature(full, digest, oid)
	if n <= 0 {
		t.Fatalf("Wc_EncodeSignature: %d", n)
	}

	buf := make([]byte, n+16)
	for i := range buf {
		buf[i] = 0xA5
	}
	short := buf[:n-1]
	if ret := Wc_EncodeSignature(short, digest, oid); ret != BAD_FUNC_ARG {
		t.Fatalf("short output: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	for i := len(short); i < len(buf); i++ {
		if buf[i] != 0xA5 {
			t.Fatalf("wrote past end of output at offset %d", i)
		}
	}

	exact := make([]byte, n)
	if ret := Wc_EncodeSignature(exact, digest, oid); ret != n {
		t.Fatalf("exact output: got %d, want %d", ret, n)
	}
	for i := range exact {
		if exact[i] != full[i] {
			t.Fatalf("exact output differs at %d", i)
		}
	}

	if ret := Wc_EncodeSignature(full, make([]byte, 512), oid); ret != BAD_FUNC_ARG {
		t.Fatalf("oversized digest: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestCurve25519LegacyExportStaysBigEndian(t *testing.T) {
	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	priv := make([]byte, 32)
	ret := Wc_curve25519_make_priv(rng, priv)
	if ret == notCompiledE {
		t.Skip("Curve25519 not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_curve25519_make_priv: %d", ret)
	}
	key := new(Curve25519_key)
	if ret := Wc_curve25519_init(key); ret != 0 {
		t.Fatalf("Wc_curve25519_init: %d", ret)
	}
	defer Wc_curve25519_free(key)
	if ret := Wc_curve25519_import_private(priv, key); ret != 0 {
		t.Fatalf("Wc_curve25519_import_private: %d", ret)
	}
	legacy := make([]byte, 32)
	if ret := Wc_curve25519_export_private_raw(key, legacy); ret != 0 {
		t.Fatalf("Wc_curve25519_export_private_raw: %d", ret)
	}
	for i := range priv {
		if legacy[i] != priv[len(priv)-1-i] {
			t.Fatalf("legacy export is not big-endian:\n got %x\n priv %x", legacy, priv)
		}
	}
	if ret := Wc_curve25519_export_private_raw_ex(key, legacy, 7); ret != BAD_FUNC_ARG {
		t.Fatalf("unknown endian: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestCurve25519ExportMatchesRfc7748Encoding(t *testing.T) {
	priv := []byte{
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
		0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
		0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
	}
	wantPub := []byte{
		0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
		0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
		0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
		0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
	}
	key := new(Curve25519_key)
	if ret := Wc_curve25519_init(key); ret == notCompiledE {
		t.Skip("Curve25519 not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_curve25519_init: %d", ret)
	}
	defer Wc_curve25519_free(key)
	if ret := Wc_curve25519_import_private(priv, key); ret != 0 {
		t.Fatalf("Wc_curve25519_import_private: %d", ret)
	}
	exported := make([]byte, 32)
	if ret := Wc_curve25519_export_private_raw_ex(key, exported, EC25519_LITTLE_ENDIAN); ret != 0 {
		t.Fatalf("Wc_curve25519_export_private_raw_ex: %d", ret)
	}
	pub := make([]byte, 32)
	if ret := Wc_curve25519_make_pub(pub, exported); ret != 0 {
		t.Fatalf("Wc_curve25519_make_pub on exported key: %d", ret)
	}
	for i := range wantPub {
		if pub[i] != wantPub[i] {
			t.Fatalf("public key from exported scalar:\n got %x\nwant %x", pub, wantPub)
		}
	}
}

func TestCurve25519PrivateExportImportRoundTrip(t *testing.T) {
	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	priv := make([]byte, 32)
	ret := Wc_curve25519_make_priv(rng, priv)
	if ret == notCompiledE {
		t.Skip("Curve25519 not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_curve25519_make_priv: %d", ret)
	}
	key := new(Curve25519_key)
	if ret := Wc_curve25519_init(key); ret != 0 {
		t.Fatalf("Wc_curve25519_init: %d", ret)
	}
	defer Wc_curve25519_free(key)
	if ret := Wc_curve25519_import_private(priv, key); ret != 0 {
		t.Fatalf("Wc_curve25519_import_private: %d", ret)
	}
	out := make([]byte, 32)
	if ret := Wc_curve25519_export_private_raw_ex(key, out, EC25519_LITTLE_ENDIAN); ret != 0 {
		t.Fatalf("Wc_curve25519_export_private_raw_ex: %d", ret)
	}
	for i := range priv {
		if out[i] != priv[i] {
			t.Fatalf("exported private key differs from imported:\n got %x\nwant %x", out, priv)
		}
	}
}

func TestBlake2sHmacDeprecatedWrapperMatchesEx(t *testing.T) {
	want := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	ret := Wc_Blake2s_HMAC_ex(want, []byte("msg"), []byte("key"), WC_BLAKE2S_256_DIGEST_SIZE)
	if ret == notCompiledE {
		t.Skip("BLAKE2s not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_Blake2s_HMAC_ex: %d", ret)
	}
	got := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	Wc_Blake2s_HMAC(got, []byte("msg"), []byte("key"), WC_BLAKE2S_256_DIGEST_SIZE)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("wrapper output %x differs from %x", got, want)
		}
	}
}

func TestBlake2sHmacReportsErrors(t *testing.T) {
	out := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	ret := Wc_Blake2s_HMAC_ex(out, []byte("msg"), []byte("key"), WC_BLAKE2S_256_DIGEST_SIZE)
	if ret == notCompiledE {
		t.Skip("BLAKE2s not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_Blake2s_HMAC_ex: %d", ret)
	}
	if ret := Wc_Blake2s_HMAC_ex(out, []byte("msg"), []byte("key"), WC_BLAKE2S_128_DIGEST_SIZE); ret != BAD_FUNC_ARG {
		t.Fatalf("unsupported outlen: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_Blake2s_HMAC_ex(out[:16], []byte("msg"), []byte("key"), WC_BLAKE2S_256_DIGEST_SIZE); ret != BAD_FUNC_ARG {
		t.Fatalf("short out: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func sha256Available() bool {
	out := make([]byte, WC_SHA256_DIGEST_SIZE)
	return Wc_Sha256Hash([]byte("x"), 1, out) != notCompiledE
}

func skipWithoutSha256(t *testing.T) {
	t.Helper()
	if !sha256Available() {
		t.Skip("SHA-256 not compiled")
	}
}

func TestHmacFinalShortOutput(t *testing.T) {
	skipWithoutSha256(t)
	hmac := Wc_HmacAllocAligned()
	if hmac == nil {
		t.Fatal("Wc_HmacAllocAligned failed")
	}
	defer Wc_HmacFreeAllocAligned(hmac)
	if ret := Wc_HmacInit(hmac, nil, INVALID_DEVID); ret != 0 {
		t.Fatalf("Wc_HmacInit: %d", ret)
	}
	defer Wc_HmacFree(hmac)
	key := []byte("hmac key long enough for fips mode")
	if ret := Wc_HmacSetKey(hmac, WC_SHA256, key, len(key)); ret != 0 {
		t.Fatalf("Wc_HmacSetKey: %d", ret)
	}
	buf := make([]byte, WC_SHA256_DIGEST_SIZE)
	for i := range buf {
		buf[i] = 0xA5
	}
	short := buf[:WC_SHA256_DIGEST_SIZE/2]
	if ret := Wc_HmacFinal(hmac, short); ret != BAD_FUNC_ARG {
		t.Fatalf("short out: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	for i := len(short); i < len(buf); i++ {
		if buf[i] != 0xA5 {
			t.Fatalf("wrote past end of output at offset %d", i)
		}
	}
	if ret := Wc_HmacFinal(hmac, buf); ret != 0 {
		t.Fatalf("full out: %d", ret)
	}
}

func TestChaChaPolyRejectsWrongKeyAndIvLength(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	plain := []byte("plaintext")
	ct := make([]byte, len(plain))
	tag := make([]byte, 16)
	ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, nil, plain, ct, tag)
	if ret == notCompiledE {
		t.Skip("ChaCha20-Poly1305 not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_ChaCha20Poly1305_Encrypt: %d", ret)
	}
	longKey := make([]byte, CHACHA20_POLY1305_AEAD_KEYSIZE+1)
	longIv := make([]byte, CHACHA20_POLY1305_AEAD_IV_SIZE+1)
	if ret := Wc_ChaCha20Poly1305_Encrypt(longKey, iv, nil, plain, ct, tag); ret != BAD_FUNC_ARG {
		t.Fatalf("encrypt long key: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_ChaCha20Poly1305_Encrypt(key, longIv, nil, plain, ct, tag); ret != BAD_FUNC_ARG {
		t.Fatalf("encrypt long iv: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	out := make([]byte, len(plain))
	if ret := Wc_ChaCha20Poly1305_Decrypt(longKey, iv, nil, ct, tag, out); ret != BAD_FUNC_ARG {
		t.Fatalf("decrypt long key: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_ChaCha20Poly1305_Decrypt(key, longIv, nil, ct, tag, out); ret != BAD_FUNC_ARG {
		t.Fatalf("decrypt long iv: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

const testUnlockFailE = -287
const testLockFailE = -192

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestHKDFPropagatesPrivateKeyGateStatus(t *testing.T) {
	skipWithoutSha256(t)
	defer forcePrivateKeyGate(false, 0, 0)
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := bytes.Repeat([]byte{0x5a}, 32)
	info := []byte("info")
	run := func() ([]byte, int) {
		out := make([]byte, 32)
		return out, Wc_HKDF(WC_SHA256, ikm, len(ikm), salt, len(salt), info, len(info), out, len(out))
	}
	if _, ret := run(); ret == notCompiledE {
		t.Skip("HKDF not compiled")
	}

	forcePrivateKeyGate(true, testUnlockFailE, 0)
	out, ret := run()
	if ret != testUnlockFailE || !isAllZero(out) || privateKeyGateLockCalls() != 0 {
		t.Fatalf("unlock failure: ret %d, out %x, lock calls %d", ret, out, privateKeyGateLockCalls())
	}

	forcePrivateKeyGate(true, 0, testLockFailE)
	out, ret = run()
	if ret != testLockFailE || isAllZero(out) || privateKeyGateLockCalls() != 1 {
		t.Fatalf("lock failure: ret %d, lock calls %d", ret, privateKeyGateLockCalls())
	}
}

func TestHKDFKnownAnswer(t *testing.T) {
	skipWithoutSha256(t)
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	// salt is the HMAC key, so it must meet the FIPS 14-byte minimum
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	want, _ := hex.DecodeString("01541ab9f2902b89038dab768f1706b15bf8e650095af780520009758f4b690a9ce9416dadcda61c4206")
	out := make([]byte, len(want))
	ret := Wc_HKDF(WC_SHA256, ikm, len(ikm), salt, len(salt), info, len(info), out, len(out))
	if ret == notCompiledE {
		t.Skip("HKDF not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_HKDF: %d", ret)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("HKDF output mismatch:\n got %x\nwant %x", out, want)
	}
}

func checkPrivateKeyGate(t *testing.T, name string, run func() ([]byte, int)) {
	t.Helper()
	defer forcePrivateKeyGate(false, 0, 0)
	forcePrivateKeyGate(true, testUnlockFailE, 0)
	out, ret := run()
	if ret != testUnlockFailE || !isAllZero(out) || privateKeyGateLockCalls() != 0 {
		t.Errorf("%s unlock failure: ret %d, out %x, lock calls %d", name, ret, out, privateKeyGateLockCalls())
	}
	forcePrivateKeyGate(true, 0, testLockFailE)
	out, ret = run()
	if ret != testLockFailE || isAllZero(out) || privateKeyGateLockCalls() != 1 {
		t.Errorf("%s lock failure: ret %d, lock calls %d", name, ret, privateKeyGateLockCalls())
	}
}

func TestPBKDF2AndEccPropagatePrivateKeyGateStatus(t *testing.T) {
	pwd := []byte("passwordPASSWORDpassword")
	salt := []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt")
	pbkdf2 := func() ([]byte, int) {
		out := make([]byte, 32)
		return out, Wc_PBKDF2(out, pwd, len(pwd), salt, len(salt), 1000, len(out), WC_SHA256)
	}
	if _, ret := pbkdf2(); ret != notCompiledE && sha256Available() {
		checkPrivateKeyGate(t, "PBKDF2", pbkdf2)
	}

	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	keys := make([]*Ecc_key, 2)
	for i := range keys {
		keys[i] = new(Ecc_key)
		if ret := Wc_ecc_init(keys[i]); ret == notCompiledE {
			t.Skip("ECC not compiled")
		} else if ret != 0 {
			t.Fatalf("Wc_ecc_init: %d", ret)
		}
		defer Wc_ecc_free(keys[i])
		if ret := Wc_ecc_make_key(rng, 32, keys[i]); ret == notCompiledE {
			t.Skip("ECC not compiled")
		} else if ret != 0 {
			t.Fatalf("Wc_ecc_make_key: %d", ret)
		}
	}
	checkPrivateKeyGate(t, "export_private_only", func() ([]byte, int) {
		out := make([]byte, 32)
		n := len(out)
		return out, Wc_ecc_export_private_only(keys[0], out, &n)
	})
	checkPrivateKeyGate(t, "export_x963_ex", func() ([]byte, int) {
		out := make([]byte, 65)
		n := len(out)
		return out, Wc_ecc_export_x963_ex(keys[0], out, &n, 0)
	})
	if ret := Wc_ecc_set_rng(keys[0], rng); ret != 0 {
		t.Fatalf("Wc_ecc_set_rng: %d", ret)
	}
	checkPrivateKeyGate(t, "shared_secret", func() ([]byte, int) {
		out := make([]byte, 32)
		n := len(out)
		return out, Wc_ecc_shared_secret(keys[0], keys[1], out, &n)
	})
}

func TestPBKDF2KnownAnswer(t *testing.T) {
	skipWithoutSha256(t)
	pwd := []byte("passwordPASSWORDpassword")
	salt := []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt")
	want, _ := hex.DecodeString("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
	out := make([]byte, len(want))
	ret := Wc_PBKDF2(out, pwd, len(pwd), salt, len(salt), 4096, len(out), WC_SHA256)
	if ret == notCompiledE {
		t.Skip("PBKDF2 not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_PBKDF2: %d", ret)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("PBKDF2 output mismatch:\n got %x\nwant %x", out, want)
	}
}

func TestRsaExponentFitsLong(t *testing.T) {
	cases := []struct {
		e    int64
		bits uint
		want bool
	}{
		{65537, 32, true},
		{1<<31 - 1, 32, true},
		{1 << 31, 32, false},
		{-(1 << 31), 32, true},
		{-(1 << 31) - 1, 32, false},
		{1 << 40, 32, false},
		{1 << 40, 64, true},
		{-1 << 63, 64, true},
	}
	for _, c := range cases {
		if got := rsaExponentFitsLong(c.e, c.bits); got != c.want {
			t.Errorf("rsaExponentFitsLong(%d, %d) = %v, want %v", c.e, c.bits, got, c.want)
		}
	}
}

func TestMakeRsaKeyRejectsSizeOutOfIntRange(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("needs 64-bit int")
	}
	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	key := new(RsaKey)
	if ret := Wc_InitRsaKey(key); ret == notCompiledE {
		t.Skip("RSA not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_InitRsaKey: %d", ret)
	}
	defer Wc_FreeRsaKey(key)
	wide := uint64(1)<<32 + 2048
	size := int(wide)
	if ret := Wc_MakeRsaKey(key, size, 65537, rng); ret != BAD_FUNC_ARG {
		t.Fatalf("size %d: got %d, want %d", size, ret, BAD_FUNC_ARG)
	}
}

// hugeTestSlice maps 4 GiB of inaccessible address space so length checks
// can be exercised without committing memory; any access faults.
func hugeTestSlice(t *testing.T) ([]byte, func()) {
	t.Helper()
	if strconv.IntSize < 64 {
		t.Skip("needs 64-bit int")
	}
	var n uint64 = 1 << 32
	b, unmap, err := mapInaccessible(int(n))
	if err != nil {
		t.Skipf("cannot reserve address space: %v", err)
	}
	return b, unmap
}

func TestCurve25519ExportRejectsOversizedBuffer(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("needs 64-bit int")
	}
	var n uint64 = 1<<32 + 32
	huge, unmap, err := mapInaccessible(int(n))
	if err != nil {
		t.Skipf("cannot reserve address space: %v", err)
	}
	defer unmap()
	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	priv := make([]byte, 32)
	if ret := Wc_curve25519_make_priv(rng, priv); ret == notCompiledE {
		t.Skip("Curve25519 not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_curve25519_make_priv: %d", ret)
	}
	key := new(Curve25519_key)
	if ret := Wc_curve25519_init(key); ret != 0 {
		t.Fatalf("Wc_curve25519_init: %d", ret)
	}
	defer Wc_curve25519_free(key)
	if ret := Wc_curve25519_import_private(priv, key); ret != 0 {
		t.Fatalf("Wc_curve25519_import_private: %d", ret)
	}
	if ret := Wc_curve25519_export_private_raw_ex(key, huge, EC25519_LITTLE_ENDIAN); ret != BAD_FUNC_ARG {
		t.Fatalf("got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestRngGenerateBlockRejectsOversizedLength(t *testing.T) {
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	if ret := Wc_RNG_GenerateBlock(rng, huge, len(huge)); ret != BAD_FUNC_ARG {
		t.Fatalf("got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestSha256UpdateRejectsOversizedLength(t *testing.T) {
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	sha := new(Wc_Sha256)
	if ret := Wc_InitSha256_ex(sha, nil, INVALID_DEVID); ret == notCompiledE {
		t.Skip("SHA-256 not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_InitSha256_ex: %d", ret)
	}
	defer Wc_Sha256Free(sha)
	if ret := Wc_Sha256Update(sha, huge, len(huge)); ret != BAD_FUNC_ARG {
		t.Fatalf("got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestBlake2sUpdateRejectsOversizedLength(t *testing.T) {
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	b2s := new(Blake2s)
	if ret := Wc_InitBlake2s(b2s, WC_BLAKE2S_256_DIGEST_SIZE); ret == notCompiledE {
		t.Skip("BLAKE2s not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_InitBlake2s: %d", ret)
	}
	if ret := Wc_Blake2sUpdate(b2s, huge, len(huge)); ret != BAD_FUNC_ARG {
		t.Fatalf("got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func newTestHmac(t *testing.T) *Hmac {
	t.Helper()
	hmac := Wc_HmacAllocAligned()
	if hmac == nil {
		t.Fatal("Wc_HmacAllocAligned failed")
	}
	if ret := Wc_HmacInit(hmac, nil, INVALID_DEVID); ret != 0 {
		Wc_HmacFreeAllocAligned(hmac)
		t.Fatalf("Wc_HmacInit: %d", ret)
	}
	return hmac
}

func freeTestHmac(hmac *Hmac) {
	Wc_HmacFree(hmac)
	Wc_HmacFreeAllocAligned(hmac)
}

func TestHmacUpdateRejectsOversizedLength(t *testing.T) {
	skipWithoutSha256(t)
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	hmac := newTestHmac(t)
	defer freeTestHmac(hmac)
	key := []byte("hmac key long enough for fips mode")
	if ret := Wc_HmacSetKey(hmac, WC_SHA256, key, len(key)); ret != 0 {
		t.Fatalf("Wc_HmacSetKey: %d", ret)
	}
	if ret := Wc_HmacUpdate(hmac, huge, len(huge)); ret != BAD_FUNC_ARG {
		t.Fatalf("got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestAesGcmRejectsOversizedLengths(t *testing.T) {
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	aes := Wc_AesAllocAligned()
	if aes == nil {
		t.Skip("AES not available")
	}
	defer Wc_AesFreeAllocAligned(aes)
	if ret := Wc_AesInit(aes, nil, INVALID_DEVID); ret != 0 {
		t.Fatalf("Wc_AesInit: %d", ret)
	}
	defer Wc_AesFree(aes)
	key := make([]byte, AES_128_KEY_SIZE)
	if ret := Wc_AesGcmSetKey(aes, key, len(key)); ret == notCompiledE {
		t.Skip("AES-GCM not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_AesGcmSetKey: %d", ret)
	}
	iv := make([]byte, GCM_NONCE_MID_SZ)
	tag := make([]byte, AES_BLOCK_SIZE)
	if ret := Wc_AesGcmEncrypt(aes, nil, nil, iv, tag, nil); ret != 0 {
		t.Fatalf("empty encrypt: %d", ret)
	}

	if ret := Wc_AesGcmEncrypt(aes, huge, huge, iv, make([]byte, AES_BLOCK_SIZE), nil); ret != BAD_FUNC_ARG {
		t.Fatalf("encrypt oversized plaintext: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_AesGcmEncrypt(aes, nil, nil, iv, make([]byte, AES_BLOCK_SIZE), huge); ret != BAD_FUNC_ARG {
		t.Fatalf("encrypt oversized AAD: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_AesGcmDecrypt(aes, huge, huge, iv, tag, nil); ret != BAD_FUNC_ARG {
		t.Fatalf("decrypt oversized ciphertext: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_AesGcmDecrypt(aes, nil, nil, iv, tag, huge); ret != BAD_FUNC_ARG {
		t.Fatalf("decrypt oversized AAD: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestChaChaPolyRejectsOversizedLengths(t *testing.T) {
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	key := make([]byte, CHACHA20_POLY1305_AEAD_KEYSIZE)
	iv := make([]byte, CHACHA20_POLY1305_AEAD_IV_SIZE)
	tag := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
	one := make([]byte, 1)
	ct := make([]byte, 1)
	ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, nil, one, ct, tag)
	if ret == notCompiledE {
		t.Skip("ChaCha20-Poly1305 not compiled")
	}
	if ret != 0 {
		t.Fatalf("encrypt: %d", ret)
	}
	scratch := make([]byte, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
	if ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, nil, huge, huge, scratch); ret != BAD_FUNC_ARG {
		t.Fatalf("encrypt oversized plaintext: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_ChaCha20Poly1305_Encrypt(key, iv, huge, one, make([]byte, 1), scratch); ret != BAD_FUNC_ARG {
		t.Fatalf("encrypt oversized AAD: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_ChaCha20Poly1305_Decrypt(key, iv, nil, huge, tag, huge); ret != BAD_FUNC_ARG {
		t.Fatalf("decrypt oversized ciphertext: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_ChaCha20Poly1305_Decrypt(key, iv, huge, ct, tag, make([]byte, 1)); ret != BAD_FUNC_ARG {
		t.Fatalf("decrypt oversized AAD: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestAesSetKeyRejectsShortIv(t *testing.T) {
	aes := Wc_AesAllocAligned()
	if aes == nil {
		t.Skip("AES not available")
	}
	defer Wc_AesFreeAllocAligned(aes)
	if ret := Wc_AesInit(aes, nil, INVALID_DEVID); ret != 0 {
		t.Fatalf("Wc_AesInit: %d", ret)
	}
	defer Wc_AesFree(aes)
	key := make([]byte, AES_128_KEY_SIZE)
	iv := make([]byte, AES_IV_SIZE)
	if ret := Wc_AesSetKey(aes, key, len(key), iv, AES_ENCRYPTION); ret == notCompiledE {
		t.Skip("AES not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_AesSetKey: %d", ret)
	}
	if ret := Wc_AesSetKey(aes, key, len(key), nil, AES_ENCRYPTION); ret != 0 {
		t.Fatalf("Wc_AesSetKey without iv: %d", ret)
	}
	if ret := Wc_AesSetKey(aes, key, len(key), iv[:AES_IV_SIZE/2], AES_ENCRYPTION); ret != BAD_FUNC_ARG {
		t.Fatalf("short iv: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestAesCbcRejectsOversizedLength(t *testing.T) {
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	aes := Wc_AesAllocAligned()
	if aes == nil {
		t.Skip("AES not available")
	}
	defer Wc_AesFreeAllocAligned(aes)
	if ret := Wc_AesInit(aes, nil, INVALID_DEVID); ret != 0 {
		t.Fatalf("Wc_AesInit: %d", ret)
	}
	defer Wc_AesFree(aes)
	key := make([]byte, AES_128_KEY_SIZE)
	iv := make([]byte, AES_IV_SIZE)
	if ret := Wc_AesSetKey(aes, key, len(key), iv, AES_ENCRYPTION); ret == notCompiledE {
		t.Skip("AES not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_AesSetKey: %d", ret)
	}
	if ret := Wc_AesCbcEncrypt(aes, make([]byte, AES_BLOCK_SIZE), make([]byte, AES_BLOCK_SIZE), AES_BLOCK_SIZE); ret == notCompiledE {
		t.Skip("AES-CBC not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_AesCbcEncrypt: %d", ret)
	}
	if ret := Wc_AesCbcEncrypt(aes, huge, huge, len(huge)); ret != BAD_FUNC_ARG {
		t.Fatalf("encrypt: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_AesSetKey(aes, key, len(key), iv, AES_DECRYPTION); ret != 0 {
		t.Fatalf("Wc_AesSetKey: %d", ret)
	}
	if ret := Wc_AesCbcDecrypt(aes, huge, huge, len(huge)); ret != BAD_FUNC_ARG {
		t.Fatalf("decrypt: got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestHmacSetKeyRejectsOversizedKey(t *testing.T) {
	skipWithoutSha256(t)
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	hmac := newTestHmac(t)
	defer freeTestHmac(hmac)
	if ret := Wc_HmacSetKey(hmac, WC_SHA256, huge, len(huge)); ret != BAD_FUNC_ARG {
		t.Fatalf("got %d, want %d", ret, BAD_FUNC_ARG)
	}
}

func TestHKDFRejectsOversizedLengths(t *testing.T) {
	skipWithoutSha256(t)
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := bytes.Repeat([]byte{0x5a}, 32)
	info := []byte("info")
	out := make([]byte, 32)
	if ret := Wc_HKDF(WC_SHA256, ikm, len(ikm), salt, len(salt), info, len(info), out, len(out)); ret == notCompiledE {
		t.Skip("HKDF not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_HKDF: %d", ret)
	}
	cases := []struct {
		name string
		ret  int
	}{
		{"ikm", Wc_HKDF(WC_SHA256, huge, len(huge), salt, len(salt), info, len(info), out, len(out))},
		{"salt", Wc_HKDF(WC_SHA256, ikm, len(ikm), huge, len(huge), info, len(info), out, len(out))},
		{"info", Wc_HKDF(WC_SHA256, ikm, len(ikm), salt, len(salt), huge, len(huge), out, len(out))},
		{"out", Wc_HKDF(WC_SHA256, ikm, len(ikm), salt, len(salt), info, len(info), huge, len(huge))},
	}
	for _, c := range cases {
		if c.ret != BAD_FUNC_ARG {
			t.Errorf("oversized %s: got %d, want %d", c.name, c.ret, BAD_FUNC_ARG)
		}
	}
}

func TestBlake2sFinalDefaultSizeShortOutput(t *testing.T) {
	b2s := new(Blake2s)
	if ret := Wc_InitBlake2s(b2s, WC_BLAKE2S_256_DIGEST_SIZE); ret == notCompiledE {
		t.Skip("BLAKE2s not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_InitBlake2s: %d", ret)
	}
	buf := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE)
	for i := range buf {
		buf[i] = 0xA5
	}
	short := buf[:WC_BLAKE2S_128_DIGEST_SIZE]
	if ret := Wc_Blake2sFinal(b2s, short, 0); ret != BAD_FUNC_ARG {
		t.Fatalf("short out with default size: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	for i := len(short); i < len(buf); i++ {
		if buf[i] != 0xA5 {
			t.Fatalf("wrote past end of output at offset %d", i)
		}
	}
	if ret := Wc_Blake2sFinal(b2s, buf, 0); ret != 0 {
		t.Fatalf("full out with default size: %d", ret)
	}
}

func testEccPem(t *testing.T) ([]byte, []byte) {
	t.Helper()
	rng := newTestRNG(t)
	defer Wc_RNG_Free(rng)
	key := new(Ecc_key)
	if ret := Wc_ecc_init(key); ret == notCompiledE {
		t.Skip("ECC not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_ecc_init: %d", ret)
	}
	defer Wc_ecc_free(key)
	if ret := Wc_ecc_make_key(rng, 32, key); ret == notCompiledE {
		t.Skip("ECC not compiled")
	} else if ret != 0 {
		t.Fatalf("Wc_ecc_make_key: %d", ret)
	}
	der := make([]byte, 256)
	n := Wc_EccKeyToDer(key, der)
	if n <= 0 {
		t.Fatalf("Wc_EccKeyToDer: %d", n)
	}
	der = der[:n]
	pem := "-----BEGIN EC PRIVATE KEY-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END EC PRIVATE KEY-----\n"
	return []byte(pem), der
}

func TestKeyPemToDerWithPassphrase(t *testing.T) {
	pem, der := testEccPem(t)
	out := make([]byte, 512)
	n := Wc_KeyPemToDer(pem, out, "passphrase")
	if n == notCompiledE {
		t.Skip("PEM decoding not compiled")
	}
	if n != len(der) || !bytes.Equal(out[:n], der) {
		t.Fatalf("Wc_KeyPemToDer: got %d, want %d matching bytes", n, len(der))
	}
}

func TestBlake2sHmacLeavesTrailingOutputUntouched(t *testing.T) {
	out := make([]byte, WC_BLAKE2S_256_DIGEST_SIZE+8)
	for i := range out {
		out[i] = 0xA5
	}
	ret := Wc_Blake2s_HMAC_ex(out, []byte("msg"), []byte("key"), WC_BLAKE2S_256_DIGEST_SIZE)
	if ret == notCompiledE {
		t.Skip("BLAKE2s not compiled")
	}
	if ret != 0 {
		t.Fatalf("Wc_Blake2s_HMAC_ex: %d", ret)
	}
	for i := WC_BLAKE2S_256_DIGEST_SIZE; i < len(out); i++ {
		if out[i] != 0xA5 {
			t.Fatalf("byte %d beyond outlen was modified", i)
		}
	}
}

func TestAesInitRejectsGoHeapHint(t *testing.T) {
	aes := Wc_AesAllocAligned()
	if aes == nil {
		t.Skip("AES not available")
	}
	defer Wc_AesFreeAllocAligned(aes)
	if ret := Wc_AesInit(aes, []byte{0}, INVALID_DEVID); ret != BAD_FUNC_ARG {
		if ret == 0 {
			Wc_AesFree(aes)
		}
		t.Fatalf("non-nil heap: got %d, want %d", ret, BAD_FUNC_ARG)
	}
	if ret := Wc_AesInit(aes, nil, INVALID_DEVID); ret != 0 {
		t.Fatalf("nil heap: %d", ret)
	}
	Wc_AesFree(aes)
}

func TestOneShotHashesRejectOversizedInput(t *testing.T) {
	huge, unmap := hugeTestSlice(t)
	defer unmap()
	out := make([]byte, 64)
	hashes := []struct {
		name string
		fn   func([]byte, int, []byte) int
	}{
		{"md5", Wc_Md5Hash},
		{"sha1", Wc_ShaHash},
		{"sha256", Wc_Sha256Hash},
		{"sha384", Wc_Sha384Hash},
		{"sha512", Wc_Sha512Hash},
	}
	for _, h := range hashes {
		if ret := h.fn([]byte("abc"), 3, out); ret == notCompiledE {
			continue
		} else if ret != 0 {
			t.Fatalf("%s: %d", h.name, ret)
		}
		if ret := h.fn(huge, len(huge), out); ret != BAD_FUNC_ARG {
			t.Errorf("%s oversized input: got %d, want %d", h.name, ret, BAD_FUNC_ARG)
		}
	}
}
