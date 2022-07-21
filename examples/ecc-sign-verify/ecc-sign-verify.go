package main

import (
    "os"
    "fmt"
    wolfSSL "github.com/wolfssl/go-wolfssl"
)

const BYTE_SZ = 8

func sign_verify(eccKeySz int, hash []byte, printSig int) {
    /* Declare variables */
    var key wolfSSL.Ecc_key
    var rng wolfSSL.WC_RNG
    var sig []byte = nil
    var max int    = wolfSSL.ECC_MAX_SIG_SIZE

    /* Algorithm for mod EG: (C / B) + (C % B != 0 ? 1:0)
     * equivalent to the calculation below              */
    byteField := int((eccKeySz + (BYTE_SZ - 1)) / BYTE_SZ)

    fmt.Println("Signing sha512 hash with key of size", eccKeySz, "and byteField of", byteField)

    sig = make([]byte, max)

    /* Initialize ecc key */
    ret := wolfSSL.Wc_ecc_init(&key)
    if ret != 0 {
        fmt.Println("Failed to initialize ecc_key")
        os.Exit(1)
    }

    /* Initialize rng */
    ret = wolfSSL.Wc_InitRng(&rng)
    if ret != 0 {
        fmt.Println("Failed to initialize rng")
        os.Exit(1)
    }

    /* Make ecc key with calculated byteField */
    ret = wolfSSL.Wc_ecc_make_key(&rng, byteField, &key)
    if ret != 0 {
        fmt.Println("Failed to make ecc key")
        os.Exit(1)
    }

    /* Sign the sha512 hash with ecc key*/
    ret = wolfSSL.Wc_ecc_sign_hash(hash, len(hash), sig, &max, &rng, &key)
    if ret != 0 {
        fmt.Println("Failed to sign hash")
        os.Exit(1)
    }

    /* Print signature hex, decided by printSig in main() */
    if printSig != 0 {
        fmt.Printf("Signature: % x \n", string(sig[0:max]))
    }

    verified := 0

    /* Verify the hash with the signature and ensure verified var is set to 1*/
    ret = wolfSSL.Wc_ecc_verify_hash(sig, max, hash, len(hash), &verified, &key)
    if ret != 0 || verified != 1 {
        fmt.Println("Failed to verify hash")
        os.Exit(1)
    }

    fmt.Println("Successfully verified signature w/ ecc key size", eccKeySz,"!")
}

func main() {
    var hash      []byte
    var str       []byte
    var printSig  int = 0 //change to 1 to print the signature hex

    /* Example string to test ecc signing */
    str = []byte("String to hash and test sign/verify")


    /* Create sha512 hash of the test string */
    hash = make([]byte, wolfSSL.WC_SHA512_DIGEST_SIZE)
    wolfSSL.Wc_Sha512Hash(str, len(str), hash)

    /* Test sign/verify for different key sizes */
    sign_verify(48,  hash, printSig)
    sign_verify(112, hash, printSig)
    sign_verify(128, hash, printSig)
    sign_verify(192, hash, printSig)
    sign_verify(256, hash, printSig)
    sign_verify(320, hash, printSig)
    sign_verify(348, hash, printSig)

}
