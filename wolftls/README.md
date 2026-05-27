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

Running `Read` and `Write` concurrently on a single `Conn` requires wolfSSL
built with `--enable-writedup`; otherwise the two calls will serialize on a
shared mutex.
