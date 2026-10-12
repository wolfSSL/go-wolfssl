/* aes-encrypt.go
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
    "bytes"
    "errors"
    "fmt"
    "os"
    "strconv"
    wolfSSL "github.com/wolfssl/go-wolfssl"
    "golang.org/x/term"
)

/* File format: magic | salt | nonce | ciphertext | tag. The header is authenticated as AAD. */
const MAGIC = "wGCM"
const MAGIC_SIZE = len(MAGIC)
const SALT_SIZE = 8
const NONCE_SIZE = wolfSSL.GCM_NONCE_MID_SZ
const TAG_SIZE = wolfSSL.AES_BLOCK_SIZE
const HEADER_SIZE = MAGIC_SIZE + SALT_SIZE + NONCE_SIZE

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

func sealData(aes *wolfSSL.Aes, password []byte, plaintext []byte, size int) ([]byte, error) {
    var rng    wolfSSL.WC_RNG
    var header []byte = make([]byte, HEADER_SIZE)
    var tag    []byte = make([]byte, TAG_SIZE)

    copy(header, MAGIC)
    salt  := header[MAGIC_SIZE:MAGIC_SIZE+SALT_SIZE]
    nonce := header[MAGIC_SIZE+SALT_SIZE:]

    output := make([]byte, len(plaintext))

    ret := wolfSSL.Wc_InitRng(&rng)
    if ret != 0 {
        return nil, errors.New("Failed to initialize RNG")
    }

    ret = wolfSSL.Wc_RNG_GenerateBlock(&rng, salt, SALT_SIZE)
    if ret == 0 {
        ret = wolfSSL.Wc_RNG_GenerateBlock(&rng, nonce, NONCE_SIZE)
    }
    freeRet := wolfSSL.Wc_FreeRng(&rng)
    if ret != 0 {
        return nil, errors.New("Failed to generate RNG block")
    }
    if freeRet != 0 {
        return nil, errors.New("Failed to free RNG")
    }

    derivedKey := make([]byte, size)
    ret = wolfSSL.Wc_PBKDF2(derivedKey, password, len(password), salt, SALT_SIZE, 4096, size, wolfSSL.WC_SHA256)
    if ret != 0 {
        return nil, errors.New("Failed to stretch key")
    }

    ret = wolfSSL.Wc_AesGcmSetKey(aes, derivedKey, size)
    if ret != 0 {
        return nil, fmt.Errorf("Failed to set AES key %d", ret)
    }

    ret = wolfSSL.Wc_AesGcmEncrypt(aes, output, plaintext, nonce, tag, header)
    if ret != 0 {
        return nil, fmt.Errorf("Failed AES encrypt %d", ret)
    }

    sealed := make([]byte, 0, HEADER_SIZE + len(output) + TAG_SIZE)
    sealed = append(sealed, header...)
    sealed = append(sealed, output...)
    sealed = append(sealed, tag...)
    return sealed, nil
}

func checkFormat(data []byte) error {
    if len(data) < HEADER_SIZE + TAG_SIZE {
        return errors.New("File too short or corrupted")
    }
    if !bytes.Equal(data[:MAGIC_SIZE], []byte(MAGIC)) {
        return errors.New("Unsupported file format (not produced by this AES-GCM example)")
    }
    return nil
}

func openData(aes *wolfSSL.Aes, password []byte, data []byte, size int) ([]byte, error) {
    if err := checkFormat(data); err != nil {
        return nil, err
    }

    header     := data[:HEADER_SIZE]
    salt       := header[MAGIC_SIZE:MAGIC_SIZE+SALT_SIZE]
    nonce      := header[MAGIC_SIZE+SALT_SIZE:]
    ciphertext := data[HEADER_SIZE:len(data)-TAG_SIZE]
    tag        := data[len(data)-TAG_SIZE:]

    output := make([]byte, len(ciphertext))

    derivedKey := make([]byte, size)
    ret := wolfSSL.Wc_PBKDF2(derivedKey, password, len(password), salt, SALT_SIZE, 4096, size, wolfSSL.WC_SHA256)
    if ret != 0 {
        return nil, errors.New("Failed to stretch key")
    }

    ret = wolfSSL.Wc_AesGcmSetKey(aes, derivedKey, size)
    if ret != 0 {
        return nil, fmt.Errorf("Failed to set AES key %d", ret)
    }

    ret = wolfSSL.Wc_AesGcmDecrypt(aes, output, ciphertext, nonce, tag, header)
    if ret != 0 {
        return nil, errors.New("Authentication failed: wrong password or corrupted file")
    }
    return output, nil
}

func writeFile(outFile string, data []byte) {
    out, err := os.Create(outFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }
    defer out.Close()

    _, err = out.Write(data)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }
}

func AesEncrypt(aes *wolfSSL.Aes, inFile string, outFile string, size int) {
    key := getPass()

    input, err := os.ReadFile(inFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    sealed, err := sealData(aes, key, input, size)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    writeFile(outFile, sealed)
}

func AesDecrypt(aes *wolfSSL.Aes, inFile string, outFile string, size int) {
    input, err := os.ReadFile(inFile)
    if err != nil {
        println(err.Error())
        os.Exit(1)
    }

    if err = checkFormat(input); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    key := getPass()

    output, err := openData(aes, key, input, size)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    writeFile(outFile, output)
}

func main() {
    /* Ensure file and keySize are given as args */
    if len(os.Args) != 5 {
        fmt.Println("Usage: ./aes-encrypt <infile name> <outfile name> <enc/dec> <key size>");
        os.Exit(1)
    }

    aes := wolfSSL.Wc_AesAllocAligned()
    if aes == nil {
        fmt.Println("Failed to allocate aligned Aes struct")
        os.Exit(1)
    }
    defer wolfSSL.Wc_AesFreeAllocAligned(aes)

    inFile     := os.Args[1]
    outFile    := os.Args[2]
    operation  := os.Args[3]
    size, _    := strconv.Atoi(os.Args[4])

    sizeCheck(&size)

    wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
    defer wolfSSL.Wc_AesFree(aes)

    if operation == "enc" {
        AesEncrypt(aes, inFile, outFile, size)
    } else if operation == "dec" {
        AesDecrypt(aes, inFile, outFile, size)
    } else {
        fmt.Println("Invalid operation. Please use enc or dec.");
        fmt.Println("Usage: ./aesEncrypt <infile name> <outfile name> <enc/dec> <key size>");
    }
}
