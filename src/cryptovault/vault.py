# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""The vault: composes key derivation, AEAD and FEC strategies."""

from cryptovault.cipher import Aes256GcmSivCipher
from cryptovault.fec import NoFec
from cryptovault.kdf import Argon2Kdf


class CryptoVault:
    """The crate's ``CryptoVault``."""

    def __init__(self, kdf: Argon2Kdf, cipher: Aes256GcmSivCipher, fec: NoFec) -> None:
        """Compose the three strategies."""

    def decrypt_with_key(self, key: bytes, blob: str) -> str:
        """Decrypt a data blob."""
        raise NotImplementedError
