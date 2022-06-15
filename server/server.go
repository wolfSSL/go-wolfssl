package main

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
    /* Server Key and Certificate paths */
    CERT_FILE := "../certs/server-cert.pem"
    KEY_FILE  := "../certs/server-key.pem"

    /* Initialize wolfSSL */
    wolfSSL.WolfSSL_Init()

    /* Create WOLFSSL_CTX with tlsv12 */
    ctx := wolfSSL.WolfSSL_CTX_new(wolfSSL.WolfTLSv1_2_server_method())
    if ctx == nil {
        fmt.Println(" WolfSSL_CTX_new Failed");
        os.Exit(1)
    }

    /* Load server certificates into WOLFSSL_CTX */
    ret := wolfSSL.WolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, wolfSSL.SSL_FILETYPE_PEM)
    if ret != wolfSSL.WOLFSSL_SUCCESS {
        fmt.Println("Error: WolfSSL_CTX_use_certificate Failed");
        os.Exit(1)
    }

    /* Load server key into WOLFSSL_CTX */
    ret = wolfSSL.WolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, wolfSSL.SSL_FILETYPE_PEM)
    if ret != wolfSSL.WOLFSSL_SUCCESS {
        fmt.Println("Error: WolfSSL_CTX_use_PrivateKey Failed");
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

