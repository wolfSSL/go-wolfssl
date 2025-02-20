package ocsp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

// Response represents an OCSP response
type Response struct {
	Status                     int
	SerialNumber              []byte
	ProducedAt                time.Time
	ThisUpdate                time.Time
	NextUpdate                time.Time
	RevokedAt                 time.Time
	RevocationReason          int
	Certificate               []byte
	IssuerHash               string
	IssuerKeyHash            []byte
	IssuerNameHash           []byte
}

// Request represents an OCSP request
type Request struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   asn1.RawValue
}
