# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""The vault composes any strategy that follows the protocols (CV-01, CV-04)."""

import pytest

from cryptovault.cipher import Aes256GcmSivCipher, AuthenticatedCipher
from cryptovault.error import CryptoVaultError
from cryptovault.fec import ErrorCorrection, NoFec
from cryptovault.kdf import Argon2Kdf, KeyDerivation
from cryptovault.vault import CryptoVault


class ReversingFec:
    """A toy codec that is not NoFec: it stores the payload reversed."""

    def encode(self, data: bytes) -> bytes:
        return data[::-1]

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        return encoded[::-1][:pre_len]

    def validate_pre_fec(self, received: bytes) -> int:
        return len(received)


def test_shipped_and_custom_strategies_satisfy_the_protocols() -> None:
    assert isinstance(Argon2Kdf(), KeyDerivation)
    assert isinstance(Aes256GcmSivCipher(), AuthenticatedCipher)
    assert isinstance(NoFec(), ErrorCorrection)
    assert isinstance(ReversingFec(), ErrorCorrection)
    vault = CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), ReversingFec())
    key = bytes(range(32))
    blob = vault.encrypt_with_key(key, "secret")
    assert vault.decrypt_with_key(key, blob) == "secret"
    # A blob decodes only with the strategy that encoded it.
    nofec = CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())
    with pytest.raises(CryptoVaultError):
        nofec.decrypt_with_key(key, blob)
