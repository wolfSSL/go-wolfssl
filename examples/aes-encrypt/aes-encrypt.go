package main

import (
    "os"
    "fmt"
    "golang.org/x/term"
    "strconv"
    wolfSSL "github.com/wolfssl/go-wolfssl"
)

const SALT_SIZE = 8

func sizeCheck(size *int) {
    if *size == 128 {
        *size = wolfSSL.AES_128_KEY_SIZE
    } else if *size == 192 {
        *size = wolfSSL.AES_192_KEY_SIZE
    } else if *size == 256 {
        *size = wolfSSL.AES_256_KEY_SIZE
    } else {
        fmt.Println("Invalid AES key size. Use 128, 192 or 256")
        os.Exit(1)
    }
}

func getPass() []byte {

    fmt.Printf("Enter password: ")

    stdin     := int(os.Stdin.Fd())
    pass, err := term.ReadPassword(stdin)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    fmt.Println()

    return pass
}

func AesEncrypt(aes wolfSSL.Aes, inFile string, outFile string, size int) {
    var rng    wolfSSL.WC_RNG
    var input  []byte
    var output []byte
    var iv     []byte = make([]byte, wolfSSL.AES_BLOCK_SIZE)
    var salt   []byte = make([]byte, SALT_SIZE)

    var length      int
    var inputLength int
    var padCounter  int = 0
    var i           int

    key := getPass()

    readIn, err := os.ReadFile(inFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    inputLength = len(readIn)
    length = inputLength
    i = inputLength

    for length % wolfSSL.AES_BLOCK_SIZE != 0 {
        length++
        padCounter++
    }

    input  = make([]byte, length)
    output = make([]byte, length)
    copy(input[0:length-padCounter], readIn[:])

    for i < length {
        input[i] = byte(padCounter)
        i++
    }

    ret := wolfSSL.Wc_InitRng(&rng)
    if ret != 0 {
        fmt.Println("Failed to initialize RNG")
        os.Exit(1)
    }

    ret = wolfSSL.Wc_RNG_GenerateBlock(&rng, iv, wolfSSL.AES_BLOCK_SIZE)
    if ret != 0 {
        fmt.Println("Failed to generate RNG block")
        os.Exit(1)
    }

    ret = wolfSSL.Wc_RNG_GenerateBlock(&rng, salt, SALT_SIZE)
    if ret != 0 {
        fmt.Println("Failed to generate RNG block")
        os.Exit(1)
    }

    if padCounter == 0 {
        salt[0] = 0
    } else if salt[0] == 0 {
        salt[0] = 1
    }

    ret = wolfSSL.Wc_PBKDF2(key, key, len(key), salt, SALT_SIZE, 4096, size, wolfSSL.WC_SHA256)
    if ret != 0 {
        fmt.Println("Failed to stretch key")
        os.Exit(1)
    }

    ret = wolfSSL.Wc_AesSetKey(&aes, key, size, iv, wolfSSL.AES_ENCRYPTION)
    if ret != 0 {
        fmt.Println("Failed to set AES key", ret)
        os.Exit(1)
    }

    ret = wolfSSL.Wc_AesCbcEncrypt(&aes, output, input, length)
    if ret != 0 {
        fmt.Println("Failed AES encrypt")
        os.Exit(1)
    }

    out, err := os.Create(outFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    _, err = out.Write(salt[0:SALT_SIZE])
    _, err = out.Write(iv[0:wolfSSL.AES_BLOCK_SIZE])
    _, err = out.Write(output[0:length])
    if err != nil {
        println(err.Error())
    }

    ret = wolfSSL.Wc_FreeRng(&rng)
    if ret != 0 {
        fmt.Println("Failed to free RNG")
        os.Exit(1)
    }
}

func AesDecrypt(aes wolfSSL.Aes, inFile string, outFile string, size int) {
    var rng    wolfSSL.WC_RNG
    var output []byte
    var iv     []byte = make([]byte, wolfSSL.AES_BLOCK_SIZE)
    var salt   []byte = make([]byte, SALT_SIZE)

    var length      int
    var inputLength int
    var i           int = 0

    input, err := os.ReadFile(inFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    inputLength = len(input)
    length = inputLength

    output = make([]byte, length)

    key := getPass()

    for i < SALT_SIZE {
        salt[i] = input[i]
        i++
    }

    i = SALT_SIZE
    for i < (wolfSSL.AES_BLOCK_SIZE + SALT_SIZE) {
        iv[i - SALT_SIZE] = input[i]
        i++
    }

    ret := wolfSSL.Wc_InitRng(&rng)
    if ret != 0 {
        fmt.Println("Failed to initialize RNG")
        os.Exit(1)
    }

    ret = wolfSSL.Wc_PBKDF2(key, key, len(key), salt, SALT_SIZE, 4096, size, wolfSSL.WC_SHA256)
    if ret != 0 {
        fmt.Println("Failed to stretch key")
        os.Exit(1)
    }

    ret = wolfSSL.Wc_AesSetKey(&aes, key, size, iv, wolfSSL.AES_DECRYPTION)
    if ret != 0 {
        fmt.Println("Failed to set AES key", ret)
        os.Exit(1)
    }

    length -= (wolfSSL.AES_BLOCK_SIZE + SALT_SIZE)

    i = 0
    for i < length {
        input[i] = input[i + (SALT_SIZE + wolfSSL.AES_BLOCK_SIZE)]
        i++
    }

    ret = wolfSSL.Wc_AesCbcDecrypt(&aes, output, input, length)
    if ret != 0 {
        fmt.Println("Failed AES encrypt",ret)
        os.Exit(1)
    }

    out, err := os.Create(outFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    _, err = out.Write(output[0:length])
    if err != nil {
        println(err.Error())
    }

    ret = wolfSSL.Wc_FreeRng(&rng)
    if ret != 0 {
        fmt.Println("Failed to free RNG")
        os.Exit(1)
    }
}

func main() {
    /* Ensure file and keySize are given as args */
    if len(os.Args) != 5 {
        fmt.Println("Usage: ./aes-encrypt <infile name> <outfile name> <enc/dec> <key size>");
        os.Exit(1)
    }

    var aes    wolfSSL.Aes

    inFile     := os.Args[1]
    outFile    := os.Args[2]
    operation  := os.Args[3]
    size, _    := strconv.Atoi(os.Args[4])

    sizeCheck(&size)

    if operation == "enc" {
        AesEncrypt(aes, inFile, outFile, size)
    } else if operation == "dec" {
        AesDecrypt(aes, inFile, outFile, size)
    } else {
        fmt.Println("Invalid operation. Please use enc or dec.");
        fmt.Println("Usage: ./aesEncrypt <infile name> <outfile name> <enc/dec> <key size>");
    }

}
