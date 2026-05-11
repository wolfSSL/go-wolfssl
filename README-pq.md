# Post-Quantum Wrappers for go-wolfssl

This document describes the ML-KEM and ML-DSA wrappers added by the
`feat/mlkem-mldsa-wrappers` branch.

## Primitives added

| File | Algorithm | NIST standard | wolfSSL API |
|------|-----------|---------------|-------------|
| `mlkem.go` | ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 | FIPS 203 | `wc_MlKemKey_*` |
| `dilithium.go` | ML-DSA-44 / ML-DSA-65 / ML-DSA-87 | FIPS 204 | `wc_dilithium_*` |

## Build prerequisites

### ML-KEM only (no experimental flag required on recent wolfSSL)

```
./configure --enable-mlkem
make
sudo make install
```

The symbol `WOLFSSL_HAVE_MLKEM` must be present in `wolfssl/options.h`.
`mlkem.go` is compiled unconditionally; when the symbol is absent every
function returns an error at runtime (the `#ifndef` stubs return `-174`).

### ML-DSA (requires `--enable-experimental` on wolfSSL master)

```
./configure --enable-mlkem --enable-dilithium
make
sudo make install
```

`dilithium.go` and `dilithium_test.go` carry the `//go:build dilithium`
constraint and are only compiled when you pass `-tags dilithium`.  This
ensures the package builds cleanly against a standard wolfSSL installation
that does not have Dilithium enabled.

```
# Build with ML-DSA support
go build -tags dilithium .

# Run all tests (ML-KEM + ML-DSA)
go test -tags dilithium -count=1 ./...

# Run only ML-KEM tests (no special wolfSSL build needed)
go test -count=1 ./...
```

## Sample usage

### ML-KEM key exchange

```go
import wolfssl "github.com/wolfssl/go-wolfssl"

// Key generation
pub, priv, err := wolfssl.MlKemGenerateKey(wolfssl.MlKemLevel768)

// Encapsulate (sender side)
ciphertext, sharedSecretA, err := wolfssl.MlKemEncapsulate(wolfssl.MlKemLevel768, pub)

// Decapsulate (recipient side)
sharedSecretB, err := wolfssl.MlKemDecapsulate(wolfssl.MlKemLevel768, priv, ciphertext)

// sharedSecretA == sharedSecretB
```

Available levels: `MlKemLevel512`, `MlKemLevel768`, `MlKemLevel1024`.

Size constants: `MLKEM_512_PUB_SIZE`, `MLKEM_512_PRIV_SIZE`,
`MLKEM_512_CIPHERTEXT_SIZE`, `MLKEM_512_SHARED_SIZE` (and likewise for 768
and 1024).

### ML-DSA sign / verify

```go
// +build dilithium

import wolfssl "github.com/wolfssl/go-wolfssl"

// Key generation
pub, priv, err := wolfssl.MlDsaGenerateKey(wolfssl.MlDsaLevel65)

// Sign
sig, err := wolfssl.MlDsaSign(wolfssl.MlDsaLevel65, priv, []byte("hello"))

// Verify
ok, err := wolfssl.MlDsaVerify(wolfssl.MlDsaLevel65, pub, []byte("hello"), sig)
// ok == true
```

Available levels: `MlDsaLevel44` (ML-DSA-44), `MlDsaLevel65` (ML-DSA-65),
`MlDsaLevel87` (ML-DSA-87).

