package random

import (
	"bytes"
	"testing"
)

func TestReader(t *testing.T) {
	r, err := NewReader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Test reading different sizes
	sizes := []int{1, 16, 32, 64, 128, 256}
	for _, size := range sizes {
		b1 := make([]byte, size)
		b2 := make([]byte, size)

		n, err := r.Read(b1)
		if err != nil {
			t.Errorf("failed to read %d bytes: %v", size, err)
		}
		if n != size {
			t.Errorf("read %d bytes, want %d", n, size)
		}

		n, err = r.Read(b2)
		if err != nil {
			t.Errorf("failed to read %d bytes: %v", size, err)
		}
		if n != size {
			t.Errorf("read %d bytes, want %d", n, size)
		}

		// Verify that we got different random bytes
		if bytes.Equal(b1, b2) {
			t.Errorf("got same random bytes for size %d", size)
		}
	}
}

func TestDefaultReader(t *testing.T) {
	// Test that DefaultReader works
	b := make([]byte, 32)
	n, err := DefaultReader.Read(b)
	if err != nil {
		t.Fatalf("failed to read from DefaultReader: %v", err)
	}
	if n != len(b) {
		t.Errorf("read %d bytes, want %d", n, len(b))
	}
}

func TestReaderClose(t *testing.T) {
	r, err := NewReader()
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	// Test that operations after Close fail
	b := make([]byte, 32)
	_, err = r.Read(b)
	if err == nil {
		t.Error("expected error after Close")
	}
}
