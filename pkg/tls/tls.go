// Package tls provides TLS functionality using wolfSSL
package tls

import (
    "crypto/x509"
    "github.com/wolfssl/go-wolfssl/pkg/cgo"
)

// Config contains configuration for TLS connections
type Config struct {
    Certificates []Certificate
    RootCAs     *x509.CertPool
}

// Certificate contains a certificate and its private key
type Certificate struct {
    Certificate [][]byte
    PrivateKey  interface{}
}

// Client creates a new TLS client
func Client(config *Config) (*Conn, error) {
    tls, err := cgo.NewTLS()
    if err != nil {
        return nil, err
    }

    // Load certificates
    for _, cert := range config.Certificates {
        if err := tls.LoadCertificate(cert.Certificate[0]); err != nil {
            tls.Free()
            return nil, err
        }
        if err := tls.LoadPrivateKey(cert.PrivateKey.([]byte)); err != nil {
            tls.Free()
            return nil, err
        }
    }

    // Load root CAs
    if config.RootCAs != nil {
        for _, cert := range config.RootCAs.Subjects() {
            if err := tls.LoadCA(cert); err != nil {
                tls.Free()
                return nil, err
            }
        }
    }

    return &Conn{tls: tls}, nil
}

// Conn represents a TLS connection
type Conn struct {
    tls *cgo.TLS
}

// Close closes the TLS connection
func (c *Conn) Close() error {
    c.tls.Free()
    return nil
}
