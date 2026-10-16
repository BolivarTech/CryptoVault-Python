# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Authenticated encryption byte-compatible with the cryptovault Rust crate."""

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
    SALT_LEN,
    TAG_LEN,
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
    "SALT_LEN",
    "TAG_LEN",
]
