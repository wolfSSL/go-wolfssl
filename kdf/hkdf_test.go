package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHKDF(t *testing.T) {
	tests := []struct {
		secret  string
		salt    string
		info    string
		outLen  int
		want    string
	}{
		{
			secret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "000102030405060708090a0b0c",
			info:   "f0f1f2f3f4f5f6f7f8f9",
			outLen: 42,
			want:   "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
	}

	for i, tt := range tests {
		secret, _ := hex.DecodeString(tt.secret)
		salt, _ := hex.DecodeString(tt.salt)
		info, _ := hex.DecodeString(tt.info)
		want, _ := hex.DecodeString(tt.want)

		got, err := HKDF(secret, salt, info, tt.outLen)
		if err != nil {
			t.Errorf("test %d: HKDF failed: %v", i, err)
			continue
		}

		if !bytes.Equal(got, want) {
			t.Errorf("test %d: got %x, want %x", i, got, want)
		}
	}
}
