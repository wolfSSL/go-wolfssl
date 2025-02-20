package internal

// #cgo CFLAGS: -I${SRCDIR}/../../../../include
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
import "C"
import "unsafe"

type Ecc_key = C.struct_ecc_key

const (
    ECC_MAX_SIG_SIZE = int(C.ECC_MAX_SIG_SIZE)
    ECC_SECP256R1 = int(C.ECC_SECP256R1)
)

func Wc_ecc_init(key *Ecc_key) int {
    return int(C.wc_ecc_init(key))
}

func Wc_ecc_free(key *Ecc_key) int {
    return int(C.wc_ecc_free(key))
}

func Wc_ecc_make_key(rng *C.struct_WC_RNG, keySize int, key *Ecc_key) int {
    return int(C.wc_ecc_make_key(rng, C.int(keySize), key))
}

func Wc_ecc_sign_hash(in []byte, inLen int, out []byte, outLen *int, rng *C.struct_WC_RNG, key *Ecc_key) int {
    return int(C.wc_ecc_sign_hash((*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
               (*C.uchar)(unsafe.Pointer(&out[0])), (*C.word32)(unsafe.Pointer(outLen)), rng, key))
}

func Wc_ecc_verify_hash(sig []byte, sigLen int, hash []byte, hashLen int, res *int, key *Ecc_key) int {
    return int(C.wc_ecc_verify_hash((*C.uchar)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
               (*C.uchar)(unsafe.Pointer(&hash[0])), C.word32(hashLen), (*C.int)(unsafe.Pointer(res)), key))
}
