package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/asn.h>
// #include <wolfssl/wolfcrypt/ecc.h>
import "C"
import (
    "crypto"
    "encoding/asn1"
    "errors"
    "math/big"
    "time"
)

// X509 constants
const (
    WC_ASN_NAME_MAX = int(C.ASN_NAME_MAX)
)

// ParseCertificate parses an X.509 certificate from ASN.1 DER data
func ParseCertificate(der []byte) (*Certificate, error) {
    var cert C.DecodedCert
    ret := C.wc_InitDecodedCert(&cert, (*C.byte)(unsafe.Pointer(&der[0])), C.word32(len(der)), nil)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_FreeDecodedCert(&cert)

    ret = C.wc_ParseCert(&cert, C.CERT_TYPE, C.NO_VERIFY, nil)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }

    // Convert to Go certificate structure
    result := &Certificate{
        Raw:                der,
        SignatureAlgorithm: getSignatureAlgorithm(cert.signatureOID),
        PublicKeyAlgorithm: getPublicKeyAlgorithm(cert.keyOID),
        Version:            int(cert.version),
        SerialNumber:       new(big.Int).SetBytes(C.GoBytes(unsafe.Pointer(cert.serial), C.int(cert.serialSz))),
        Issuer:            convertName(&cert.issuer),
        Subject:           convertName(&cert.subject),
        NotBefore:         time.Unix(int64(cert.beforeDate), 0),
        NotAfter:          time.Unix(int64(cert.afterDate), 0),
    }

    return result, nil
}

// CreateCertificate creates a new X.509 certificate based on a template
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) ([]byte, error) {
    cert := C.Cert{}
    ret := C.wc_InitCert(&cert)
    if ret != 0 {
        return nil, WolfSSLError(ret)
    }
    defer C.wc_FreeCert(&cert)

    // Set certificate fields from template
    if template.SerialNumber != nil {
        serial := template.SerialNumber.Bytes()
        if len(serial) > 0 {
            C.wc_SetSerial(&cert, (*C.byte)(unsafe.Pointer(&serial[0])), C.int(len(serial)))
        }
    }

    // Set validity period
    C.wc_SetDateInfo(&cert, C.long(template.NotBefore.Unix()), C.long(template.NotAfter.Unix()))

    // Generate certificate
    var derBuffer [8192]byte
    derLen := C.wc_MakeCert(&cert, (*C.byte)(unsafe.Pointer(&derBuffer[0])), 8192, nil)
    if derLen <= 0 {
        return nil, WolfSSLError(int(derLen))
    }

    // Sign the certificate
    sigLen := C.wc_SignCert(C.int(derLen), C.int(cert.sigType), (*C.byte)(unsafe.Pointer(&derBuffer[0])), &cert)
    if sigLen <= 0 {
        return nil, WolfSSLError(int(sigLen))
    }

    return C.GoBytes(unsafe.Pointer(&derBuffer[0]), C.int(sigLen)), nil
}
