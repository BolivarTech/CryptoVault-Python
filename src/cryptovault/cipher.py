# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""AEAD strategy: AES-256-GCM-SIV."""


class Aes256GcmSivCipher:
    """AES-256-GCM-SIV."""

    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        """Seal ``plaintext``."""
        raise NotImplementedError

    def decrypt(self, key: bytes, nonce: bytes, aad: bytes, sealed: bytes) -> bytes:
        """Open ``sealed``."""
        raise NotImplementedError
