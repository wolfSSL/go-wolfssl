package sha256

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestNew(t *testing.T) {
	h := New()
	if h == nil {
		t.Fatal("New() returned nil")
	}
	if h.Size() != 32 {
		t.Errorf("Size() = %d, want 32", h.Size())
	}
	if h.BlockSize() != 64 {
		t.Errorf("BlockSize() = %d, want 64", h.BlockSize())
	}
}

func TestWrite(t *testing.T) {
	h := New()
	data := []byte("test data")
	n, err := h.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Errorf("Write() = %d, want %d", n, len(data))
	}
}

func TestSum(t *testing.T) {
	h := New()
	data := []byte("test data")
	h.Write(data)
	sum := h.Sum(nil)
	if len(sum) != 32 {
		t.Errorf("Sum() length = %d, want 32", len(sum))
	}

	// Compare with crypto/sha256
	expected := sha256.Sum256(data)
	if !bytes.Equal(sum, expected[:]) {
		t.Error("Sum() result does not match crypto/sha256")
	}
}

func TestReset(t *testing.T) {
	h := New()
	data1 := []byte("test data 1")
	data2 := []byte("test data 2")

	h.Write(data1)
	sum1 := h.Sum(nil)

	h.Reset()
	h.Write(data2)
	sum2 := h.Sum(nil)

	if bytes.Equal(sum1, sum2) {
		t.Error("Reset() did not clear hash state")
	}
}

func TestSum256(t *testing.T) {
	data := []byte("test data")
	sum := Sum256(data)

	// Compare with crypto/sha256
	expected := sha256.Sum256(data)
	if sum != expected {
		t.Error("Sum256() result does not match crypto/sha256")
	}
}
