# CryptoVault-Python

**A Python implementation of the [`cryptovault`](https://github.com/BolivarTech/cryptovault)
blob format, byte-compatible with the Rust crate.** AES-256-GCM-SIV under an HKDF-SHA256 key,
Argon2id key derivation and DEK/KEK key wrapping, followed by the crate's forward-error
correction: Reed-Solomon, an interleaver and a Viterbi code, or no FEC at all.

> **Status: 0.3.0, alpha.** Every FEC strategy of `cryptovault` 0.3.0 is implemented and
> checked in both directions against the crate.

---

## What it does

Two services that share a 32-byte key can encrypt and authenticate messages for each other.
A blob made on either side opens on the other, Rust → Python and Python → Rust. The package
opens no connections and knows nothing about transports: it turns text or key material into
a blob and back, and the caller moves the blob.

The Rust crate stacks two independent layers: an AEAD that provides all of the security,
then an FEC that adds channel resilience and no security. Both are implemented here, with
the same four FEC strategies as the crate.

## Installation

```sh
pip install cryptovault-py
```

The import name is `cryptovault`. [Requirements](#requirements) lists the supported Python versions and the `cryptography` and
OpenSSL floor.

## Quick start

```python
>>> from cryptovault import CryptoVault, generate_dek, generate_salt
>>> vault = CryptoVault.default()             # Argon2id + AES-256-GCM-SIV + concatenated FEC

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

`CryptoVault.default()` matches `CryptoVault::default()` in Rust. To pick another FEC
strategy, compose the vault yourself; the constructor has no defaults:

```python
>>> from cryptovault import Aes256GcmSivCipher, Argon2Kdf, NoFec
>>> aead_only = CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())
>>> aead_only.decrypt_with_key(key, aead_only.encrypt_with_key(key, "hi"))
'hi'

```

`derive_key(password, salt)` runs Argon2id with the crate's OWASP-2025 profile (64 MiB, three
passes, four lanes). Call it once per session and keep the key.

### Blob layout

```text
blob    = base64( fec.encode( header ‖ nonce(12 B) ‖ ciphertext ‖ tag(16 B) ) )   standard, padded
header  = version (0x01) ‖ plaintext_len (u32, little-endian)
key     = HKDF-SHA256( salt = none, ikm = 32-byte master key, info = "cryptovault:v1:aead", L = 32 )
AAD     = purpose ‖ header ‖ aad_extra
purpose = 0x01 data · 0x02 wrapped key
extra   = empty for data · the salt for a wrapped key (authenticated, never stored)
cipher  = AES-256-GCM-SIV, fresh random 12-byte nonce per message
```

The header is bound as associated data, so changing any bit of it fails authentication. The purpose byte keeps a data blob from opening as a wrapped key, and
the other way round. As for the version byte, it leaves room for the format to evolve; today
only `0x01` is accepted.

## FEC strategies

The FEC layer sits after the AEAD and only helps a blob survive a noisy channel. Correction
is all or nothing. Within capacity the blob comes back exact; past it, decryption fails with
a typed error and never returns wrong plaintext, because the AEAD tag checks the result.

| Strategy | Pipeline | Corrects | Size of a 1 KiB message |
|---|---|---|---|
| `ConcatenatedFec.default()` | RS(255, 223) → depth-5 block interleaver → Viterbi K=7 R=1/2 | scattered bit errors and bursts | 3404 B |
| `ConcatenatedFec.with_csprng_from_master(master, depth)` | the same, plus a keyed shuffle per window | as above, weaker burst spreading | 3404 B |
| `ViterbiOnlyFec()` | Viterbi K=7 R=1/2 | scattered bit errors | 2824 B |
| `ReedSolomonCodec()` | RS(255, 223) | up to 16 bad bytes per 255-byte codeword | 1700 B |
| `NoFec()` | none | nothing; any change fails authentication | 1412 B |

The CSPRNG variant derives its seed from the master key with HKDF (`info =
"cryptovault:v1:interleaver"`), and both ends must build it from the same master and depth.
It is obfuscation, not security.

### Speed

The Reed-Solomon and Viterbi codecs come in two implementations that produce the same bytes.
The platform wheels carry a compiled extension, `cryptovault._native`, built from the
`reedsolomon` 0.2.0 and `viterbi` 0.2.0 crates that `cryptovault` itself uses. Everywhere
else the package runs pure-Python ports of those crates. A platform with no compiled wheel
gets the `py3-none-any` one, and on an interpreter the abi3 wheels do not cover (PyPy,
free-threaded CPython) the extension does not load. Nothing needs configuring;
`cryptovault.fec._codecs.ACTIVE.name` says which one is running. Measured with CPython 3.11
on Windows:

| Strategy | Codecs | Encrypt 128 KiB | Decrypt 128 KiB | Decrypt 128 KiB, one flipped bit | Decrypt 1 KiB, one flipped bit |
|---|---|---|---|---|---|
| `ConcatenatedFec` | compiled | 0.21 s | 0.22 s | 2.2 s | 0.02 s |
| `ConcatenatedFec` | Python | 1.4 s | 1.7 s | 15.6 s | 0.16 s |
| `ViterbiOnlyFec` | compiled | 0.03 s | 0.05 s | 2.6 s | 0.02 s |
| `ViterbiOnlyFec` | Python | 0.25 s | 0.66 s | 14.3 s | 0.12 s |
| `ReedSolomonCodec` | compiled | 0.02 s | 0.04 s | 0.04 s | < 0.01 s |
| `ReedSolomonCodec` | Python | 1.1 s | 1.0 s | 0.82 s | 0.01 s |
| `NoFec` | none | < 0.01 s | < 0.01 s | fails, < 0.01 s | fails, < 0.01 s |

A clean Viterbi sub-block decodes directly with either implementation. One with channel
errors runs the full trellis: about 2 s for a full 124 950-byte sub-block with the compiled
codecs, the speed of the crate's own decoder, and about 12 s in Python.

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
- **Channel errors past the FEC capacity.** The blob fails closed and never decrypts to
  something wrong. With `NoFec`, a single flipped bit is enough.
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
- **Decode with the same FEC strategy you encoded with.** A blob from a default Rust vault
  opens with `CryptoVault.default()`; one from a `NoFec` vault needs a `NoFec` vault here.
- **Bound decrypt input from untrusted sources.** `with_max_blob_len(cap)` returns a vault
  that rejects larger blobs before any decryption work. With FEC this also bounds the decode
  time, which grows with the number of corrupted Viterbi sub-blocks.
- **One blob, one message.** Framing and delivery belong to the caller.

## Errors

Every failure is a `CryptoVaultError`. The subclass names the stage that failed, and `str()`
matches the crate's `Display` for the same input, word for word:

| Class | Raised for |
|---|---|
| `InvalidInputError` | wrong key, salt or seed length, empty password, interleave depth out of range, oversized input, malformed blob, unknown version |
| `EncodingError` | non-canonical base64, text that is not valid UTF-8 |
| `CipherError` | a tag that does not verify (wrong key, salt or purpose, any tampering) |
| `KeyDerivationError` | Argon2id failure, or no OS entropy for a salt or DEK |
| `ErrorCorrectionError` | corruption beyond the Reed-Solomon capacity, or no ChaCha20 in the backend for the CSPRNG layer |

## Compatibility testing

The test suite replays reference data that the crate itself produced. For `NoFec`: its
constants, data blobs up to 128 KiB, wrapped keys, Argon2id outputs, and the exact error for
358 adversarial inputs (every single-bit flip of a blob, truncations, bad versions and
lengths, non-canonical base64, wrong keys and salts, invalid UTF-8). For the FEC layer: the
Reed-Solomon codewords and the outcome of 146 corrupted decodes, the interleaver
permutations (the CSPRNG layer included), Viterbi encodings and 26 corrupted decodes down to
the wrong bytes a heavily damaged stream decodes to, and 335 adversarial blobs under three
strategies (sampled bit flips, bursts, truncation, rewritten headers, wrong keys and salts).
The codec cases run against both the compiled and the Python codecs. In the other
direction, a second test hands the crate blobs made in Python under every strategy and checks
that it opens each one. Before publishing, the release runs both directions again against
every built wheel, compiled and pure, installed on each platform it ships for. The generator lives in `interop/rust`:

```sh
uv run pytest                     # full suite, Rust fixtures included
uv run pytest -m interop          # Python → Rust; needs the Rust toolchain
cargo run --release --manifest-path interop/rust/Cargo.toml -- fixtures \
    > tests/fixtures/rust_nofec.json   # regenerate the NoFec fixtures
cargo run --release --manifest-path interop/rust/Cargo.toml -- fec-fixtures \
    > tests/fixtures/rust_fec.json     # regenerate the FEC fixtures
```

## Requirements

- **Python 3.11** or newer. Tested on Linux and Windows with 3.11 and 3.14. Compiled wheels
  exist for Linux (x86_64 and aarch64, glibc 2.17+ and musl), Windows x86_64 and macOS
  (universal2); any other platform gets the pure-Python wheel.
- **`cryptography` 45.0.1 or newer**, linked against **OpenSSL 3.2 or newer** (AES-GCM-SIV and
  Argon2id need it; the CSPRNG layer also uses its ChaCha20). Releases before 45.0.1 reject an empty plaintext, which the crate allows.
  The official wheels qualify.

## Development

A Rust toolchain (1.96 or newer) is needed: `uv sync` builds the extension in `native/` with
maturin, and rebuilds it whenever its sources change.

```sh
uv sync --locked
uv run ruff check . && uv run ruff format --check . && uv run mypy . && uv run pytest
uv run pip-audit
uv build
(cd native && cargo fmt --check && cargo clippy --release --all-targets -- -D warnings)
```

## License

Licensed under either of

- **MIT** license ([LICENSE-MIT](LICENSE-MIT)), or
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this package by you, as defined in the Apache-2.0 license, shall be
dual-licensed as above, without any additional terms or conditions.

Copyright © 2026 Julian Bolivar / BolivarTech.
