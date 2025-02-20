package tls

import (
    "crypto"
    "errors"
    "io"
    "net"
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
    "github.com/wolfssl/go-wolfssl/x509"
)

// Config contains configuration for TLS connections
type Config struct {
    Certificates []Certificate
    GetCertificate func(*ClientHelloInfo) (*Certificate, error)
    RootCAs *x509.CertPool
    ServerName string
    InsecureSkipVerify bool
    MinVersion uint16
    MaxVersion uint16
}

// Certificate represents a TLS certificate
type Certificate struct {
    Certificate [][]byte
    PrivateKey  crypto.PrivateKey
    Leaf        *x509.Certificate
}

// Conn represents a TLS connection
type Conn struct {
    conn     net.Conn
    config   *Config
    ctx      *cgo.WOLFSSL_CTX
    ssl      *cgo.WOLFSSL
    isClient bool
}

// ConnectionState contains information about the TLS connection
type ConnectionState struct {
    Version                    uint16
    HandshakeComplete         bool
    DidResume                 bool
    CipherSuite               uint16
    NegotiatedProtocol        string
    NegotiatedProtocolIsMutual bool
    ServerName                string
    PeerCertificates         []*x509.Certificate
    VerifiedChains           [][]*x509.Certificate
}

// ClientHelloInfo contains information from a TLS client hello
type ClientHelloInfo struct {
    CipherSuites      []uint16
    ServerName        string
    SupportedCurves   []CurveID
    SupportedPoints   []uint8
    SignatureSchemes  []SignatureScheme
    SupportedProtos   []string
    SupportedVersions []uint16
    Conn             net.Conn
}

const (
    VersionTLS12 = 0x0303
    VersionTLS13 = 0x0304
)

// Listen creates a TLS listener accepting connections on the given network address
func Listen(network, laddr string, config *Config) (net.Listener, error) {
    l, err := net.Listen(network, laddr)
    if err != nil {
        return nil, err
    }
    return NewListener(l, config), nil
}

// NewListener creates a TLS listener accepting connections from an existing listener
func NewListener(inner net.Listener, config *Config) net.Listener {
    return &listener{
        Listener: inner,
        config:  config,
    }
}

// Client initiates a TLS handshake over an existing connection
func Client(conn net.Conn, config *Config) *Conn {
    return &Conn{
        conn:     conn,
        config:   config,
        isClient: true,
    }
}

// Server initiates a TLS handshake over an existing connection
func Server(conn net.Conn, config *Config) *Conn {
    return &Conn{
        conn:     conn,
        config:   config,
        isClient: false,
    }
}

// LoadX509KeyPair reads and parses a public/private key pair from PEM files
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
    // TODO: Implement using wolfSSL
    return Certificate{}, errors.New("not implemented")
}

// X509KeyPair parses a public/private key pair from PEM-encoded data
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
    // TODO: Implement using wolfSSL
    return Certificate{}, errors.New("not implemented")
}
