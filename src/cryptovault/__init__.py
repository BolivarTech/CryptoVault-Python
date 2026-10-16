# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Authenticated encryption byte-compatible with the ``cryptovault`` Rust crate.

A blob produced here opens with the crate and the other way round, for data
and for wrapped keys, as long as both sides use the same FEC strategy. The
payload is sealed with AES-256-GCM-SIV under an HKDF-SHA256 sub-key, with the
header bound as associated data, and then protected for the channel by one of
the crate's FEC strategies (see :mod:`cryptovault.fec`).

Example:
    >>> from cryptovault import CryptoVault, generate_dek
    >>> vault = CryptoVault.default()
    >>> key = generate_dek()
    >>> blob = vault.encrypt_with_key(key, "sk-secret")
    >>> vault.decrypt_with_key(key, blob)
    'sk-secret'
"""

from cryptovault.cipher import Aes256GcmSivCipher, AuthenticatedCipher
from cryptovault.constants import (
    ARGON2_M_KIB,
    ARGON2_P,
    ARGON2_T,
    BLOB_VERSION,
    HEADER_LEN,
    KEY_LEN,
    MAX_B64_LEN,
    MAX_BLOB_LEN,
    MAX_PLAINTEXT_LEN,
    NONCE_LEN,
    RECOMMENDED_MAX_PAYLOAD,
    RS_BLOCK,
    RS_DATA,
    RS_INTERLEAVE_MAX,
    RS_PARITY,
    SALT_LEN,
    TAG_LEN,
    TERMINATION_OVERHEAD,
    VITERBI_CHUNK,
)
from cryptovault.error import (
    CipherError,
    CryptoVaultError,
    EncodingError,
    ErrorCorrectionError,
    InvalidInputError,
    KeyDerivationError,
)
from cryptovault.fec import ConcatenatedFec, ErrorCorrection, NoFec
from cryptovault.kdf import Argon2Kdf, KeyDerivation
from cryptovault.vault import (
    CryptoVault,
    constant_time_eq,
    generate_dek,
    generate_salt,
)

__all__ = [
    "ARGON2_M_KIB",
    "ARGON2_P",
    "ARGON2_T",
    "BLOB_VERSION",
    "HEADER_LEN",
    "KEY_LEN",
    "MAX_B64_LEN",
    "MAX_BLOB_LEN",
    "MAX_PLAINTEXT_LEN",
    "NONCE_LEN",
    "RECOMMENDED_MAX_PAYLOAD",
    "RS_BLOCK",
    "RS_DATA",
    "RS_INTERLEAVE_MAX",
    "RS_PARITY",
    "SALT_LEN",
    "TAG_LEN",
    "TERMINATION_OVERHEAD",
    "VITERBI_CHUNK",
    "Aes256GcmSivCipher",
    "Argon2Kdf",
    "AuthenticatedCipher",
    "CipherError",
    "ConcatenatedFec",
    "CryptoVault",
    "CryptoVaultError",
    "EncodingError",
    "ErrorCorrection",
    "ErrorCorrectionError",
    "InvalidInputError",
    "KeyDerivation",
    "KeyDerivationError",
    "NoFec",
    "constant_time_eq",
    "generate_dek",
    "generate_salt",
]
