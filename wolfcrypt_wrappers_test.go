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
