package main

import (
    "os"
    "fmt"
    wolfSSL "github.com/wolfssl/go-wolfssl"
)

func main() {
    /* Ensure file and alg are given as args */
    if len(os.Args) != 3 {
        fmt.Println("Usage: ./file-hash <algorithm> <file name>");
        os.Exit(1)
    }

    var out []byte
    alg := os.Args[1]
    inFile := os.Args[2]

    /* Read in the file to be hashed */
    str, err := os.ReadFile(inFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    var ret int

    /* Hash the input based on chosen algorithm */
    if alg == "sha" {
        out = make([]byte, wolfSSL.WC_SHA_DIGEST_SIZE )
        ret = wolfSSL.Wc_ShaHash(str, len(str), out)
    } else if alg == "sha256" {
        out = make([]byte, wolfSSL.WC_SHA256_DIGEST_SIZE )
        ret = wolfSSL.Wc_Sha256Hash(str, len(str), out)
    } else if alg == "sha384" {
       out = make([]byte, wolfSSL.WC_SHA384_DIGEST_SIZE )
        ret = wolfSSL.Wc_Sha384Hash(str, len(str), out)
    } else if alg == "sha512" {
        out = make([]byte, wolfSSL.WC_SHA512_DIGEST_SIZE )
        ret = wolfSSL.Wc_Sha512Hash(str, len(str), out)
    } else if alg == "md5" {
        out = make([]byte, wolfSSL.WC_MD5_DIGEST_SIZE )
        ret = wolfSSL.Wc_Md5Hash(str, len(str), out)
    } else {
        fmt.Println("Invalid algorithm. Please use sha, sha256, sha384, sha512, or md5.");
        os.Exit(1)
    }


    if ret != 0 {
        fmt.Println("Error. Hash func returned", ret);
        os.Exit(1)
    } else {
        fmt.Printf("% x \n", string(out))
    }
}
