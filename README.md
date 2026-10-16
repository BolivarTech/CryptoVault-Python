# CryptoVault-Python

**A Python implementation of the [`cryptovault`](https://github.com/BolivarTech/cryptovault)
blob format, byte-compatible with the Rust crate.** This first release covers the AEAD-only
`NoFec` mode: AES-256-GCM-SIV under an HKDF-SHA256 key, Argon2id key derivation, and
DEK/KEK key wrapping, with no forward-error-correction layer.

> **Status: 0.1.0, in development.** The `NoFec` format is implemented and checked in both
> directions against `cryptovault` 0.3.0. There is no tagged release yet, and the package is
> not on PyPI.

---

## What it does

Two services that share a 32-byte key can encrypt and authenticate messages for each other.
A blob made on either side opens on the other, Rust → Python and Python → Rust. The package
opens no connections and knows nothing about transports: it turns text or key material into
a blob and back, and the caller moves the blob.

The Rust crate stacks two independent layers: an AEAD that provides all of the security,
then an optional FEC that adds channel resilience and no security. Only the first layer is
implemented here. It is the wire format the crate produces when built with its `NoFec`
strategy.

## Quick start

```python
>>> from cryptovault import (
...     Aes256GcmSivCipher, Argon2Kdf, CryptoVault, NoFec, generate_dek, generate_salt,
... )
>>> vault = CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())

>>> key = generate_dek()                      # or vault.derive_key(password, salt)
>>> blob = vault.encrypt_with_key(key, "sk-secret")
>>> vault.decrypt_with_key(key, blob)
'sk-secret'

>>> salt = generate_salt()                    # one per context, kept by the caller
>>> kek = generate_dek()
>>> dek = generate_dek()
>>> wrapped = vault.wrap_key(kek, salt, dek)  # the salt is bound as AAD
>>> vault.unwrap_key(kek, salt, wrapped) == dek
True

```

The vault has no default FEC strategy on purpose. `CryptoVault::default()` in Rust uses the
concatenated FEC, and a Python default of `NoFec` would produce blobs it cannot read.

`derive_key(password, salt)` runs Argon2id with the crate's OWASP-2025 profile (64 MiB, three
passes, four lanes). Call it once per session and keep the key.

### Blob layout

```text
blob    = base64( header ‖ nonce(12 B) ‖ ciphertext ‖ tag(16 B) )      standard alphabet, padded
header  = version (0x01) ‖ plaintext_len (u32, little-endian)
key     = HKDF-SHA256( salt = none, ikm = 32-byte master key, info = "cryptovault:v1:aead", L = 32 )
AAD     = purpose ‖ header ‖ aad_extra
purpose = 0x01 data · 0x02 wrapped key
extra   = empty for data · the salt for a wrapped key (authenticated, never stored)
cipher  = AES-256-GCM-SIV, fresh random 12-byte nonce per message
```

The header travels in the clear and is bound as associated data, so changing any bit of it
fails authentication. The purpose byte keeps a data blob from opening as a wrapped key, and
the other way round. As for the version byte, it leaves room for the format to evolve; today
only `0x01` is accepted.

## Security model

| Property | Mechanism | Level |
|---|---|---|
| Confidentiality | AES-256-GCM-SIV (RFC 8452) | 256-bit key |
| Integrity / authenticity | 128-bit GCM-SIV tag, header bound as AAD | forgery ≤ 2⁻¹²⁸ per message |
| Nonce-misuse resistance | SIV construction | a nonce collision reveals only plaintext equality |
| Key separation | HKDF-SHA256 with a fixed `info` label | the AEAD key is never the raw master key |
| Password hardening | Argon2id v1.3, m = 64 MiB, t = 3, p = 4 | OWASP 2025 profile |
| Context binding | salt and purpose bound as AAD on wrapped keys | wrong salt or purpose fails authentication |
| Typed failures | one exception class per failing stage, fixed messages | no input echoed in an error |
| Secret hygiene | no key, secret, blob or plaintext in errors, logs or `repr` | — |

All cryptographic primitives come from the [`cryptography`](https://cryptography.io/)
package. Nothing here is home-rolled crypto.

### Out of scope (what it does NOT defend against)

- **Weak passwords.** Argon2id slows guessing down; it does not make a weak password strong.
- **Replay.** A valid blob stays valid. Detecting repeats is the caller's protocol concern.
- **Traffic analysis.** The header carries the plaintext length in the clear, and the blob
  size follows from it.
- **Channel errors.** Without FEC, a single flipped bit makes the blob fail authentication.
  That is the intended behavior: it fails closed and never decrypts to something wrong.
- **Memory disclosure.** The crate wipes secrets from memory; Python's immutable `str` and
  `bytes` cannot promise that, and this package does not try.
- **Host compromise.** A key in process memory is as safe as the process.

### Operational contracts (the caller must honor)

- **Use exactly 32 bytes of key.** A shorter or longer key is an error, not something the
  package pads or truncates.
- **Use a fresh salt per context**, from `generate_salt()`. The same password and salt give
  the same key.
- **Rate-limit `derive_key` for untrusted callers.** Each call costs 64 MiB and noticeable
  CPU.
- **Rekey before ~2⁴⁸ messages per key.** That is the birthday bound for random 96-bit
  nonces.
- **Decode with the same mode you encoded with.** A default `cryptovault::CryptoVault` in Rust
  wraps the blob in FEC, which this package cannot read yet. Interoperate with a Rust vault
  built with `NoFec`.
- **Bound decrypt input from untrusted sources.** `with_max_blob_len(cap)` returns a vault
  that rejects larger blobs before any decryption work.
- **One blob, one message.** Framing and delivery belong to the caller.

## Errors

Every failure is a `CryptoVaultError`. The subclass names the stage that failed, and `str()`
matches the crate's `Display` for the same input, word for word:

| Class | Raised for |
|---|---|
| `InvalidInputError` | wrong key or salt length, empty password, oversized input, malformed blob, unknown version |
| `EncodingError` | non-canonical base64, text that is not valid UTF-8 |
| `CipherError` | a tag that does not verify (wrong key, salt or purpose, any tampering) |
| `KeyDerivationError` | Argon2id failure, or no OS entropy for a salt or DEK |
| `ErrorCorrectionError` | reserved for the FEC strategies of a later release |

## Compatibility testing

The test suite replays reference data that the crate itself produced: its constants, data
blobs up to 128 KiB, wrapped keys, Argon2id outputs, and the exact error for 358
adversarial inputs (every single-bit flip of a blob, truncations, bad versions and lengths,
non-canonical base64, wrong keys and salts, invalid UTF-8). A second test hands blobs made in
Python to the crate and checks that it opens each one. The generator lives in `interop/rust`:

```sh
uv run pytest                     # full suite, Rust fixtures included
uv run pytest -m interop          # Python → Rust; needs the Rust toolchain
cargo run --release --manifest-path interop/rust/Cargo.toml -- fixtures \
    > tests/fixtures/rust_nofec.json   # regenerate the fixtures
```

## Requirements

- **Python 3.11** or newer. Tested on Linux and Windows with 3.11 and 3.14.
- **`cryptography` 45.0.1 or newer**, linked against **OpenSSL 3.2 or newer** (AES-GCM-SIV and
  Argon2id need it). Releases before 45.0.1 reject an empty plaintext, which the crate allows.
  The official wheels qualify.

## Development

```sh
uv sync --locked
uv run ruff check . && uv run ruff format --check . && uv run mypy . && uv run pytest
uv run pip-audit
uv build
```

## Roadmap

1. **`NoFec` blob format, Argon2id and key wrapping.** Implemented and cross-checked against
   the crate in both directions.
2. **The FEC strategies.** Reed-Solomon, the interleaver and Viterbi, so any `cryptovault`
   blob can be read from Python.

## License

Licensed under either of

- **MIT** license ([LICENSE-MIT](LICENSE-MIT)), or
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this package by you, as defined in the Apache-2.0 license, shall be
dual-licensed as above, without any additional terms or conditions.

Copyright © 2026 Julian Bolivar / BolivarTech.
