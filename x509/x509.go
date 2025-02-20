package x509

import (
    "crypto"
    "encoding/asn1"
    "errors"
    "math/big"
    "net"
    "net/url"
    "time"
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
)

// Certificate represents an X.509 certificate
type Certificate struct {
    Raw                     []byte
    SignatureAlgorithm     SignatureAlgorithm
    PublicKeyAlgorithm     PublicKeyAlgorithm
    PublicKey              interface{}
    Version                int
    SerialNumber          *big.Int
    Issuer                Name
    Subject               Name
    NotBefore             time.Time
    NotAfter              time.Time
    KeyUsage              KeyUsage
    ExtKeyUsage           []ExtKeyUsage
    BasicConstraintsValid bool
    IsCA                  bool
    MaxPathLen            int
    DNSNames             []string
    EmailAddresses       []string
    IPAddresses         []net.IP
    URIs                []*url.URL
}

// PublicKeyAlgorithm identifies the type of public key in a certificate
type PublicKeyAlgorithm int

// SignatureAlgorithm identifies the type of signature on a certificate
type SignatureAlgorithm int

// KeyUsage identifies the ways in which a certificate's key may be used
type KeyUsage int

// ExtKeyUsage identifies the purposes for which a certificate's key may be used
type ExtKeyUsage int

// CertPool is a set of certificates
type CertPool struct {
    bySubjectKeyId map[string][]int
    byName         map[string][]int
    certs          []*Certificate
}

// CreateCertificate creates a new X.509 v3 certificate based on a template
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) ([]byte, error) {
    return cgo.CreateCertificate(rand, template, parent, pub, priv)
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
    return cgo.ParseCertificate(asn1Data)
}

// ParseCertificates parses one or more certificates from the given ASN.1 DER data
func ParseCertificates(asn1Data []byte) ([]*Certificate, error) {
    cert, err := ParseCertificate(asn1Data)
    if err != nil {
        return nil, err
    }
    return []*Certificate{cert}, nil
}

// NewCertPool returns a new, empty CertPool
func NewCertPool() *CertPool {
    return &CertPool{
        bySubjectKeyId: make(map[string][]int),
        byName:         make(map[string][]int),
    }
}
