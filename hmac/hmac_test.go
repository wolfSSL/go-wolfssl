package hmac

import (
    "bytes"
    "crypto/rand"
    "testing"
    "github.com/wolfssl/go-wolfssl/sha256"
)

func TestHMAC(t *testing.T) {
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        t.Fatal(err)
    }

    data := []byte("test data")
    h1 := New(sha256.New, key)
    h1.Write(data)
    sum1 := h1.Sum(nil)

    // Test that calling Sum doesn't affect the underlying hash
    sum2 := h1.Sum(nil)
    if !bytes.Equal(sum1, sum2) {
        t.Error("Sum affected the underlying hash")
    }

    // Test Reset
    h1.Reset()
    h1.Write(data)
    sum3 := h1.Sum(nil)
    if !bytes.Equal(sum1, sum3) {
        t.Error("Reset didn't restore the hash to its initial state")
    }

    // Test writing in chunks
    h2 := New(sha256.New, key)
    h2.Write(data[:4])
    h2.Write(data[4:])
    sum4 := h2.Sum(nil)
    if !bytes.Equal(sum1, sum4) {
        t.Error("Writing in chunks produced different hash")
    }
}
