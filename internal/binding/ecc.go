package binding

// #cgo CFLAGS: -I${SRCDIR}/../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
// #ifndef HAVE_ECC
// #define ECC_MAX_SIG_SIZE 1
// typedef struct ecc_key {} ecc_key;
// int wc_ecc_init(ecc_key *key) {
//      return -174;
//  }
// int wc_ecc_free(ecc_key *key) {
//      return -174;
//  }
// int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key) {
//      return -174;
//  }
// int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
//                      WC_RNG* rng, ecc_key* key) {
//      return -174;
//  }
// int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
//                        word32 hashlen, int* res, ecc_key* key) {
//      return -174;
//  }
// #endif
import "C"
// No imports needed yet

// ECC functions
func GenerateKey(curve int) ([]byte, []byte, error) {
    var key C.ecc_key
    if err := C.wc_ecc_init(&key); err != 0 {
        return nil, nil, WolfSSLError(err)
    }
    defer C.wc_ecc_free(&key)

    // Generate key
    if err := C.wc_ecc_make_key(nil, 0, &key); err != 0 {
        return nil, nil, WolfSSLError(err)
    }

    // Export private key
    var privKey [C.ECC_MAX_SIG_SIZE]byte
    var privKeyLen C.word32
    if err := C.wc_ecc_export_private_only(&key, (*C.byte)(&privKey[0]), &privKeyLen); err != 0 {
        return nil, nil, WolfSSLError(err)
    }

    // Export public key
    var pubKey [C.ECC_MAX_SIG_SIZE]byte
    var pubKeyLen C.word32
    if err := C.wc_ecc_export_x963(&key, (*C.byte)(&pubKey[0]), &pubKeyLen); err != 0 {
        return nil, nil, WolfSSLError(err)
    }

    return privKey[:privKeyLen], pubKey[:pubKeyLen], nil
}

func Sign(priv []byte, message []byte) ([]byte, error) {
    var key C.ecc_key
    if err := C.wc_ecc_init(&key); err != 0 {
        return nil, WolfSSLError(err)
    }
    defer C.wc_ecc_free(&key)

    // Import private key
    if err := C.wc_ecc_import_private_key((*C.byte)(&priv[0]), C.word32(len(priv)), nil, 0, &key); err != 0 {
        return nil, WolfSSLError(err)
    }

    // Sign message
    var sig [C.ECC_MAX_SIG_SIZE]byte
    var sigLen C.word32
    if err := C.wc_ecc_sign_hash((*C.byte)(&message[0]), C.word32(len(message)), (*C.byte)(&sig[0]), &sigLen, nil, &key); err != 0 {
        return nil, WolfSSLError(err)
    }

    return sig[:sigLen], nil
}

func Verify(pub []byte, message []byte, sig []byte) bool {
    var key C.ecc_key
    if err := C.wc_ecc_init(&key); err != 0 {
        return false
    }
    defer C.wc_ecc_free(&key)

    // Import public key
    if err := C.wc_ecc_import_x963((*C.byte)(&pub[0]), C.word32(len(pub)), &key); err != 0 {
        return false
    }

    // Verify signature
    var status C.int
    if err := C.wc_ecc_verify_hash((*C.byte)(&sig[0]), C.word32(len(sig)), (*C.byte)(&message[0]), C.word32(len(message)), &status, &key); err != 0 {
        return false
    }

    return status == 1
}
