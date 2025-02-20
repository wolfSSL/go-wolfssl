package tls

import (
    "crypto"
    "github.com/wolfssl/go-wolfssl/x509"
)

// A Certificate is a chain of one or more certificates.
type Certificate struct {
    Certificate [][]byte
    PrivateKey  crypto.PrivateKey
    Leaf        *x509.Certificate
}

// Config contains configuration parameters for TLS connections.
type Config struct {
    Certificates []Certificate
    GetCertificate func(*ClientHelloInfo) (*Certificate, error)
    RootCAs *x509.CertPool
    ServerName string
    InsecureSkipVerify bool
}

// ClientHelloInfo contains information from a TLS client hello message.
type ClientHelloInfo struct {
    ServerName string
}

// A CertPool represents a pool of certificates.
type CertPool struct {
    *x509.CertPool
}

// NewCertPool creates a new, empty cert pool.
func NewCertPool() *CertPool {
    return &CertPool{x509.NewCertPool()}
}

// X509KeyPair parses a public/private key pair from PEM encoded data.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
    cert, err := x509.ParseCertificate(certPEMBlock)
    if err != nil {
        return Certificate{}, err
    }

    key, err := x509.ParsePKCS8PrivateKey(keyPEMBlock)
    if err != nil {
        return Certificate{}, err
    }

    return Certificate{
        Certificate: [][]byte{certPEMBlock},
        PrivateKey:  key,
        Leaf:        cert,
    }, nil
}
