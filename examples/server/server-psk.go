/* server-psk.go
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
// unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
//                           unsigned char* key, unsigned int key_max_len)
//{
//    (void)ssl;
//    (void)key_max_len;
//
//    if (strncmp(identity, "Client_identity", 15) != 0) {
//        return 0;
//    }
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
    "fmt"
    "net"
    "os"
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

    /* Create WOLFSSL_CTX with tlsv13 */
    ctx := wolfSSL.WolfSSL_CTX_new(wolfSSL.WolfTLSv1_3_server_method())
    if ctx == nil {
        fmt.Println(" WolfSSL_CTX_new Failed");
        os.Exit(1)
    }

    wolfSSL.WolfSSL_CTX_set_psk_server_callback(ctx, C.my_psk_server_cb)

    ret := wolfSSL.WolfSSL_CTX_use_psk_identity_hint(ctx, "wolfssl server");
    if ret != wolfSSL.WOLFSSL_SUCCESS {
        fmt.Println(" WolfSSL_CTX_use_psk_identity_hint ", ret);
        os.Exit(1)
    }
    /* Listen for incoming connections */
    l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
    if err != nil {
        fmt.Println("Error listening:", err.Error())
        os.Exit(1)
    }
    /* Close the listener when the application closes */
    defer l.Close()
    fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)

    /* Listen for an incoming connection */
    conn, err := l.Accept()
    if err != nil {
        fmt.Println("Error accepting: ", err.Error())
    }

    /* Create a WOLFSSL object */
    ssl := wolfSSL.WolfSSL_new(ctx)
    if ssl == nil {
        fmt.Println(" WolfSSL_new Failed");
        os.Exit(1)
    }

    /* Retrieve file descriptor from net.Conn type */
    file,err := conn.(*net.TCPConn).File()
    fd := file.Fd()
    wolfSSL.WolfSSL_set_fd(ssl, int(fd))

    /* Establish TLS connection */
    ret = wolfSSL.WolfSSL_accept(ssl);
    if ret != wolfSSL.WOLFSSL_SUCCESS {
        fmt.Println(" WolfSSL_accept error ", ret);
        os.Exit(1)
    } else {
        fmt.Println("Client Succesfully Connected!");
    }

    buf := make([]byte, 256)

    /* Recieve then print the message from client */
    ret = wolfSSL.WolfSSL_read(ssl, buf, 256)
    if ret == -1 {
        fmt.Println(" WolfSSL_read failed ");
    } else {
        fmt.Println("Client says : ", string(buf));
    }

    /* Create the message and send to client */
    reply := []byte("I hear ya fashizzle!")
    sz := uintptr(len(reply))

    ret = wolfSSL.WolfSSL_write(ssl, reply, sz)
    if uintptr(ret) != sz {
        fmt.Println(" WolfSSL_write failed ");
        os.Exit(1)
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

