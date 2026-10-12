//go:build !windows
// +build !windows

/* ssl_x509_wrappers_test.go
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

package wolfSSL

import (
    "encoding/pem"
    "os"
    "syscall"
    "testing"
    "time"
)

const testCertDir = "examples/certs/"
const testNotCompiledIn = -174

type tlsTestPair struct {
    srvCtx *WOLFSSL_CTX
    cliCtx *WOLFSSL_CTX
    srv    *WOLFSSL
    cli    *WOLFSSL
    fds    [2]int
}

func readTestFile(t *testing.T, name string) []byte {
    t.Helper()
    b, err := os.ReadFile(testCertDir + name)
    if err != nil {
        t.Fatalf("read %s: %v", name, err)
    }
    return b
}

func readTestCertDER(t *testing.T, name string) []byte {
    t.Helper()
    block, _ := pem.Decode(readTestFile(t, name))
    if block == nil {
        t.Fatalf("no PEM block in %s", name)
    }
    return block.Bytes
}

func newTLSTestPair(t *testing.T) *tlsTestPair {
    t.Helper()
    WolfSSL_Init()
    p := &tlsTestPair{}
    fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
    if err != nil {
        t.Fatalf("socketpair: %v", err)
    }
    p.fds = fds
    t.Cleanup(p.free)

    p.srvCtx = WolfSSL_CTX_new_v23_server()
    p.cliCtx = WolfSSL_CTX_new_v23_client()
    if p.srvCtx == nil || p.cliCtx == nil {
        t.Fatal("CTX_new failed")
    }
    chain := readTestFile(t, "server-cert.pem")
    if WolfSSL_CTX_use_certificate_chain_buffer_format(p.srvCtx, chain,
        len(chain), SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS {
        t.Fatal("load server chain failed")
    }
    key := readTestFile(t, "server-key.pem")
    if WolfSSL_CTX_use_PrivateKey_buffer(p.srvCtx, key, len(key),
        SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS {
        t.Fatal("load server key failed")
    }
    WolfSSL_CTX_set_verify(p.cliCtx, SSL_VERIFY_NONE)

    p.srv = WolfSSL_new(p.srvCtx)
    p.cli = WolfSSL_new(p.cliCtx)
    if p.srv == nil || p.cli == nil {
        t.Fatal("WolfSSL_new failed")
    }
    WolfSSL_set_fd(p.srv, fds[0])
    WolfSSL_set_fd(p.cli, fds[1])
    return p
}

func (p *tlsTestPair) free() {
    if p.srv != nil { WolfSSL_free(p.srv) }
    if p.cli != nil { WolfSSL_free(p.cli) }
    if p.srvCtx != nil { WolfSSL_CTX_free(p.srvCtx) }
    if p.cliCtx != nil { WolfSSL_CTX_free(p.cliCtx) }
    syscall.Close(p.fds[0])
    syscall.Close(p.fds[1])
}

func (p *tlsTestPair) handshake(t *testing.T) (int, int) {
    t.Helper()
    srvRet := make(chan int, 1)
    go func() {
        ret := WolfSSL_accept(p.srv)
        if ret != WOLFSSL_SUCCESS {
            syscall.Shutdown(p.fds[0], syscall.SHUT_RDWR)
        }
        srvRet <- ret
    }()
    watchdog := time.AfterFunc(20*time.Second, func() {
        syscall.Shutdown(p.fds[0], syscall.SHUT_RDWR)
        syscall.Shutdown(p.fds[1], syscall.SHUT_RDWR)
    })
    defer watchdog.Stop()
    cliRet := WolfSSL_connect(p.cli)
    if cliRet != WOLFSSL_SUCCESS {
        syscall.Shutdown(p.fds[1], syscall.SHUT_RDWR)
    }
    return <-srvRet, cliRet
}

func requireALPN(t *testing.T) {
    t.Helper()
    WolfSSL_Init()
    ctx := WolfSSL_CTX_new_v23_client()
    if ctx == nil {
        t.Fatal("CTX_new failed")
    }
    defer WolfSSL_CTX_free(ctx)
    ssl := WolfSSL_new(ctx)
    if ssl == nil {
        t.Fatal("WolfSSL_new failed")
    }
    defer WolfSSL_free(ssl)
    if WolfSSL_UseALPN(ssl, "h2", WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) == testNotCompiledIn {
        t.Skip("wolfSSL built without ALPN")
    }
}

func TestALPNFailedOnMismatchAbortsHandshake(t *testing.T) {
    requireALPN(t)
    p := newTLSTestPair(t)
    if WolfSSL_UseALPN(p.srv, "http/1.1", WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS ||
        WolfSSL_UseALPN(p.cli, "h2", WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS {
        t.Fatal("UseALPN failed")
    }
    srvRet, cliRet := p.handshake(t)
    if srvRet == WOLFSSL_SUCCESS || cliRet == WOLFSSL_SUCCESS {
        t.Fatalf("handshake with no common ALPN protocol succeeded (srv=%d cli=%d)",
            srvRet, cliRet)
    }
}

func TestALPNContinueOnMismatchCompletesHandshake(t *testing.T) {
    requireALPN(t)
    p := newTLSTestPair(t)
    if WolfSSL_UseALPN(p.srv, "http/1.1", WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) != WOLFSSL_SUCCESS ||
        WolfSSL_UseALPN(p.cli, "h2", WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) != WOLFSSL_SUCCESS {
        t.Fatal("UseALPN failed")
    }
    srvRet, cliRet := p.handshake(t)
    if srvRet != WOLFSSL_SUCCESS || cliRet != WOLFSSL_SUCCESS {
        t.Fatalf("handshake failed (srv=%d cli=%d)", srvRet, cliRet)
    }
}

func requireOpenSSLExtra(t *testing.T, der []byte) {
    t.Helper()
    x := WolfSSL_X509_load_certificate_buffer(der, len(der), SSL_FILETYPE_ASN1)
    if x == nil {
        t.Skip("wolfSSL built without OPENSSL_EXTRA")
    }
    WolfSSL_X509_free(x)
}

func TestD2iX509ParsesDER(t *testing.T) {
    der := readTestCertDER(t, "ca-cert.pem")
    requireOpenSSLExtra(t, der)
    x := WolfSSL_d2i_X509(der)
    if x == nil {
        t.Fatal("WolfSSL_d2i_X509 failed on a valid certificate")
    }
    defer WolfSSL_X509_free(x)
    var out []byte
    if n := WolfSSL_i2d_X509(x, &out); n <= 0 || string(out) != string(der) {
        t.Fatalf("re-encoded DER differs from input (n=%d)", n)
    }
}

func TestLoadVerifyLocationsUsesCADirectory(t *testing.T) {
    dir := t.TempDir()
    if err := os.WriteFile(dir+"/ca-cert.pem", readTestFile(t, "ca-cert.pem"), 0600); err != nil {
        t.Fatal(err)
    }
    WolfSSL_Init()
    ctx := WolfSSL_CTX_new_v23_client()
    if ctx == nil {
        t.Fatal("CTX_new failed")
    }
    defer WolfSSL_CTX_free(ctx)
    if ret := WolfSSL_CTX_load_verify_locations(ctx, "", []byte(dir)); ret != WOLFSSL_SUCCESS {
        t.Fatalf("loading CA directory failed: %d", ret)
    }
    if ret := WolfSSL_CTX_load_verify_locations(ctx, testCertDir+"ca-cert.pem", nil); ret != WOLFSSL_SUCCESS {
        t.Fatalf("loading CA file failed: %d", ret)
    }
}

func TestPeerChainDERRejectsMissingEntry(t *testing.T) {
    entries := [][]byte{nil, []byte("intermediate"), []byte("root")}
    got := wrapperCollectChainDER(len(entries), func(i int) []byte { return entries[i] })
    if got != nil {
        t.Fatalf("chain with an unreadable entry returned %d certs", len(got))
    }
    entries[0] = []byte("leaf")
    got = wrapperCollectChainDER(len(entries), func(i int) []byte { return entries[i] })
    if len(got) != 3 || string(got[0]) != "leaf" || string(got[2]) != "root" {
        t.Fatalf("complete chain not returned in order: %q", got)
    }
}

func TestPeerChainDERMatchesServerChain(t *testing.T) {
    p := newTLSTestPair(t)
    srvRet, cliRet := p.handshake(t)
    if srvRet != WOLFSSL_SUCCESS || cliRet != WOLFSSL_SUCCESS {
        t.Fatalf("handshake failed (srv=%d cli=%d)", srvRet, cliRet)
    }
    rest := readTestFile(t, "server-cert.pem")
    var want [][]byte
    for {
        var block *pem.Block
        block, rest = pem.Decode(rest)
        if block == nil { break }
        want = append(want, block.Bytes)
    }
    got := WolfSSL_get_peer_cert_chain_DER(p.cli)
    if len(got) == 0 {
        t.Skip("wolfSSL built without peer certificate retention")
    }
    if len(got) == 1 {
        if string(got[0]) != string(want[0]) {
            t.Fatal("leaf differs from server certificate")
        }
        return
    }
    if len(got) != len(want) {
        t.Fatalf("got %d chain certs, want %d", len(got), len(want))
    }
    for i := range want {
        if string(got[i]) != string(want[i]) {
            t.Fatalf("chain entry %d differs", i)
        }
    }
}

func TestProtoVersionConstantsAccepted(t *testing.T) {
    WolfSSL_Init()
    ctx := WolfSSL_CTX_new_v23_client()
    if ctx == nil {
        t.Fatal("CTX_new failed")
    }
    defer WolfSSL_CTX_free(ctx)
    if WolfSSL_CTX_set_max_proto_version(ctx, 0) == testNotCompiledIn {
        t.Skip("wolfSSL built without proto version setters")
    }
    if ret := WolfSSL_CTX_set_min_proto_version(ctx, WOLFSSL_TLSV1_2); ret != WOLFSSL_SUCCESS {
        t.Fatalf("set_min_proto_version(WOLFSSL_TLSV1_2) = %d", ret)
    }
    if ret := WolfSSL_CTX_set_max_proto_version(ctx, WOLFSSL_TLSV1_3); ret != WOLFSSL_SUCCESS {
        t.Fatalf("set_max_proto_version(WOLFSSL_TLSV1_3) = %d", ret)
    }
}
