#!/bin/bash

OPTIONS_H="../wolfssl/wolfssl/options.h"

if [ -f path.txt ];then
    WOLFSSL_PATH=`cat path.txt`
    echo "Found path.txt."
    
    if [ -f "$WOLFSSL_PATH/wolfssl/options.h" ];then
        OPTIONS_H="$WOLFSSL_PATH/wolfssl/options.h"
    else
        echo "Couldn't find options.h, please supply the correct path to wolfSSL in path.txt."
        exit 99
    fi
else
    echo "Couldn't find path.txt, defaulting to ../wolfssl path."
    if [ ! -d ../wolfssl ];then
        echo "Couldn't find wolfSSL in default path, please supply the correct path to wolfSSL in path.txt."
        exit 99
    fi
fi

rm -f options.go
echo "package wolfSSL" >> options.go
echo ""                >> options.go
echo "// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl" >> options.go
echo "// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lm"                >> options.go
sed 's/^/\/\/ /' $OPTIONS_H                                           >> options.go
echo "options.go generated."

exit 0
