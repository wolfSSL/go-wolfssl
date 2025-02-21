package hmac

import (
    "bytes"
    "crypto/sha256"
    "testing"
)

func TestHMAC(t *testing.T) {
    key := []byte("test key")
    data := []byte("test data")

    // Create new HMAC-SHA256
    h := New(sha256.New)
    h.Write(data)
    sum1 := h.Sum(nil)

    // Reset and write again
    h.Reset()
    h.Write(data)
    sum2 := h.Sum(nil)

    // Verify both sums are equal
    if !bytes.Equal(sum1, sum2) {
        t.Error("HMAC sums do not match")
    }

    // Verify size
    if h.Size() != sha256.Size {
        t.Errorf("wrong Size: got %d want %d", h.Size(), sha256.Size)
    }

    // Verify block size
    if h.BlockSize() != sha256.BlockSize {
        t.Errorf("wrong BlockSize: got %d want %d", h.BlockSize(), sha256.BlockSize)
    }
}
