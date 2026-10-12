package wolfSSL

import (
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
