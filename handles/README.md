# handles

Lifecycle-managed Go wrappers around wolfCrypt primitives:

- `EccKey` — wolfCrypt P-256 ECC key + dedicated RNG; supports
  `GenerateP256Key`, `NewEmptyEccKey` (full keypair init for parse
  paths), `NewEmptyEccPubKey` (no RNG; public-key-only handles), DER /
  PEM marshal+parse (SEC1 and PKCS#8), raw point export, and digest
  signing.
- `AesGcmAEAD` — wolfCrypt AES-256-GCM that satisfies
  `crypto/cipher.AEAD`; used by control-channel Noise and TPM
  secretbox paths in tailscale.

The parent `go-wolfssl` package stays a thin one-Go-func-per-`wc_*`
direct-wrapper layer; opinionated lifecycle/marshal helpers live here.

## Algorithm tagging

`EccKey` reports `Algorithm()` returning `handles.AlgECDSAP256` for P-256
keys (`handles.AlgUnknown` for any other curve) so
algorithm-polymorphic consumers (e.g. `wolfx509.KeyHandle`) can
dispatch on the key class without type-asserting. The `handles.Algorithm`
enum is the shared algorithm taxonomy across `handles` and `wolfx509`.
