package cgo

// Key represents a cryptographic key
type Key struct {
	raw []byte
}

func (k *Key) Raw() []byte {
	return k.raw
}

func NewKey(raw []byte) *Key {
	return &Key{raw: raw}
}
