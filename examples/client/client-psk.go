/* client-psk.go
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package main

//#cgo CFLAGS: -g -Wall -I/usr/include 
//#include <string.h>
//#include <wolfssl/options.h>
//#include <wolfssl/ssl.h>
//#define PSK_KEY_LEN 4
//unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
//        char* identity, unsigned int id_max_len, unsigned char* key,
//        unsigned int key_max_len)
//{
//    (void)ssl;
//    (void)hint;
//    (void)key_max_len;
//
//    strncpy(identity, "Client_identity", id_max_len);
//
//    key[0] = 26;
//    key[1] = 43;
//    key[2] = 60;
//    key[3] = 77;
//
//    return PSK_KEY_LEN;
//}
import "C"
import (
    "net"
    "os"
    "fmt"
    wolfSSL "github.com/wolfssl/go-wolfssl"
)

/* Connection configuration constants */
const (
    CONN_HOST = "localhost"
    CONN_PORT = "11111"
    CONN_TYPE = "tcp"
)

func main() {
    /* Initialize wolfSSL */
    wolfSSL.WolfSSL_Init()

    /* Create WOLFSSL_CTX with tlsv12 */
    ctx := wolfSSL.WolfSSL_CTX_new(wolfSSL.WolfTLSv1_3_client_method())
    if ctx == nil {
        fmt.Println(" CTX new Failed");
        os.Exit(1)
    }

    wolfSSL.WolfSSL_CTX_set_psk_client_callback(ctx, C.my_psk_client_cb);

    /* Create a WOLFSSL object */
    ssl := wolfSSL.WolfSSL_new(ctx)
    if ssl == nil {
        fmt.Println(" wolfSSL_new failed");
        os.Exit(1)
    }

    /* Get address of TCP end point */
    tcpAddr, err := net.ResolveTCPAddr(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
    if err != nil {
        println("ResolveTCPAddr failed:", err.Error())
        os.Exit(1)
    }

    /* Dial the recieved TCP address */
    conn, err := net.DialTCP(CONN_TYPE, nil, tcpAddr)
    if err != nil {
        println("Dial failed:", err.Error())
        os.Exit(1)
    }

    /* Retrieve file descriptor from net.*TCPConn type */
    file,err := conn.File()
    fd := file.Fd()
    wolfSSL.WolfSSL_set_fd(ssl, int(fd))

    /* Connect to wolfSSL on the server side */
    ret := wolfSSL.WolfSSL_connect(ssl);
    if ret != wolfSSL.WOLFSSL_SUCCESS {
        fmt.Println(" wolfSSL_connect error ", ret);
        os.Exit(1)
    } else {
        fmt.Println("Succesfully Connected!");
    }

    /* Create the message and send to server */
    message := []byte("Can you hear me?")
    sz := uintptr(len(message))

    ret = wolfSSL.WolfSSL_write(ssl, message, sz)
    if uintptr(ret) != sz {
        fmt.Println(" wolfSSL_write failed ");
        os.Exit(1)
    }


    /* Recieve then print the message from server */
    buf := make([]byte, 256)
    ret = wolfSSL.WolfSSL_read(ssl, buf, 256)
    if ret == -1 {
        fmt.Println(" wolfSSL_read failed ");
    } else {
        fmt.Println("Server says : ", string(buf));
    }

    /* Shutdown wolfSSL */
    wolfSSL.WolfSSL_shutdown(ssl)
    /* Free wolfSSL and wolfSSL_CTX objects */
    wolfSSL.WolfSSL_free(ssl)
    wolfSSL.WolfSSL_CTX_free(ctx)
    /* Cleanup the wolfSSL environment */
    wolfSSL.WolfSSL_Cleanup()

    /* Close the connection */
    conn.Close()
}
