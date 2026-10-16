# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

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
