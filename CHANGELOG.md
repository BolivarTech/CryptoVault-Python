# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-16

Compiled Reed-Solomon and Viterbi codecs, with the pure-Python ones kept as the fallback.

### Added

- `cryptovault._native`, a PyO3 extension built from the `reedsolomon` 0.2.0 and `viterbi`
  0.2.0 crates the Rust crate uses. With it, a 128 KiB `ConcatenatedFec` blob decrypts in
  0.22 s instead of 1.7 s, and in 2.2 s instead of 15.6 s with one flipped bit.
- Compiled abi3 wheels for Linux (x86_64 and aarch64, manylinux 2.17 and musllinux 1.2),
  Windows x86_64 and macOS universal2, plus a `py3-none-any` wheel that runs the pure-Python
  codecs on every other platform.

### Changed

- The package builds with maturin, so building from source needs a Rust toolchain (1.96 or
  newer).

## [0.2.0] - 2026-10-16

The FEC layer of `cryptovault` 0.3.0, with every strategy of the crate, byte-compatible in
both directions.

### Added

- `ConcatenatedFec`: Reed-Solomon RS(255, 223), then an interleaver, then the CCSDS K=7
  R=1/2 Viterbi code. `ConcatenatedFec.default()` builds the crate's default stack and
  `ConcatenatedFec.with_csprng_from_master(master, depth)` the keyed variant.
- `CryptoVault.default()`, the crate's default vault: Argon2id, AES-256-GCM-SIV and the
  default concatenated FEC.
- `ReedSolomonCodec` and `ViterbiOnlyFec`, usable alone as FEC strategies.
- `BlockInterleaver`, `CsprngLayer`, `Interleaver` and `ViterbiCodec`, the stages the
  concatenated stack is built from.
- `expand_interleaver_seed`, the HKDF sub-key that seeds the CSPRNG layer.
- The constants `RS_DATA`, `RS_PARITY`, `RS_BLOCK`, `RS_INTERLEAVE_MAX`, `VITERBI_CHUNK` and
  `TERMINATION_OVERHEAD`.
- An `fec-fixtures` subcommand in the interop tool, and Python → Rust checks for every
  strategy.

### Changed

- `fec` is now a package; `from cryptovault.fec import NoFec` still works.
- The distribution is named `cryptovault-py`, the name it is published under on PyPI. The
  import name is still `cryptovault`.

## [0.1.0] - 2026-10-16

First release: the `NoFec` mode of `cryptovault` 0.3.0, byte-compatible in both directions.

### Added

- `CryptoVault`, composed from injected strategies: `Argon2Kdf`, `Aes256GcmSivCipher` and
  `NoFec`, behind the `KeyDerivation`, `AuthenticatedCipher` and `ErrorCorrection`
  protocols.
- `encrypt_with_key` and `decrypt_with_key` for text, with the crate's blob layout and its
  fixed order of checks on decryption.
- `wrap_key`, `unwrap_key` and `rewrap` for DEK/KEK envelopes, with the salt bound as AAD.
- `derive_key` with Argon2id (m = 64 MiB, t = 3, p = 4) and `with_max_blob_len` to cap the
  accepted blob size.
- `generate_salt`, `generate_dek` and `constant_time_eq`, plus the crate's public constants.
- Five error classes under `CryptoVaultError`, whose `str()` matches the crate's `Display`.
- A Rust tool under `interop/rust` that generates the reference fixtures from the crate and
  verifies Python-produced blobs with it.
