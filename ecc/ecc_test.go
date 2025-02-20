package ecc

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	pub, priv, err := GenerateKey(ECC_SECP256R1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 65 {
		t.Errorf("public key length = %d, want 65", len(pub))
	}
	if len(priv) != 32 {
		t.Errorf("private key length = %d, want 32", len(priv))
	}
}

func TestImportPrivate(t *testing.T) {
	pub, priv, err := GenerateKey(ECC_SECP256R1, nil)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ImportPrivate(ECC_SECP256R1, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Free()

	pubKey := key.Public()
	if pubKey == nil {
		t.Fatal("failed to get public key")
	}
	defer pubKey.Free()

	exportedPub, err := ExportPublicFromPrivate(key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(exportedPub, pub) {
		t.Error("exported public key does not match original")
	}
}

func TestImportPublic(t *testing.T) {
	pub, _, err := GenerateKey(ECC_SECP256R1, nil)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ImportPublic(ECC_SECP256R1, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Free()

	msg := []byte("test message")
	sig := make([]byte, 64)

	if Verify(pub, msg, sig) {
		t.Error("expected invalid signature")
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := GenerateKey(ECC_SECP256R1, nil)
	if err != nil {
		t.Fatal(err)
	}

	privKey, err := ImportPrivate(ECC_SECP256R1, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer privKey.Free()

	msg := []byte("test message")
	sig, err := Sign(privKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	// wolfSSL may return variable-length signatures
	if len(sig) < 60 || len(sig) > 72 {
		t.Errorf("signature length = %d, want between 60 and 72", len(sig))
	}

	if !Verify(pub, msg, sig) {
		t.Error("expected valid signature")
	}

	// Test invalid signature
	invalidSig := make([]byte, len(sig))
	copy(invalidSig, sig)
	invalidSig[0] ^= 0xff
	if Verify(pub, msg, invalidSig) {
		t.Error("expected invalid signature")
	}
}
