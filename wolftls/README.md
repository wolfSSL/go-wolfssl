# wolftls

A Go-idiomatic TLS package whose API shape mirrors `crypto/tls` but
whose entire handshake and record I/O runs through wolfSSL.

## Public API surface

- `Config` / `Certificate` / `ConnectionState` — `crypto/tls`-shaped
  config and cert types.
- `Conn` — `net.Conn` wrapping a wolfSSL session. `Read` preserves the
  underlying `net.Conn` error type so `net/http`'s
  `Hijacker`-via-`SetReadDeadline` path keeps working
  (`net.Error.Timeout()` is honored).
- `Listener` / `NewListener` / `Server` / `Client` — TCP+TLS wrappers.
- Per-connection callbacks: SNI (`Config.GetCertificate` /
  `GetConfigForClient`) and cert-setup; trampolines and Go I/O
  bridging are implemented in `callbacks.go`.

## Build requirements

Concurrent `Read` and `Write` on a single `Conn` are supported in any build.
With wolfSSL built with `--enable-writedup` they process records in parallel;
otherwise they take turns inside wolfSSL, but a `Read` waiting for input never
blocks a `Write`.
