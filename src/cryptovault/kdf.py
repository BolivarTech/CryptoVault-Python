# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Key-derivation strategy: Argon2id master key, HKDF-SHA256 sub-keys."""


class Argon2Kdf:
    """Argon2id with the crate's OWASP-2025 profile."""

    def derive_master(self, password: bytes, salt: bytes) -> bytes:
        """Derive the master key."""
        raise NotImplementedError
