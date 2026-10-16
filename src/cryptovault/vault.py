# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""The vault: composes key derivation, AEAD and FEC strategies."""

import base64
import struct

from cryptovault._blob import decode_blob
from cryptovault.cipher import Aes256GcmSivCipher
from cryptovault.constants import NONCE_LEN
from cryptovault.fec import NoFec
from cryptovault.kdf import Argon2Kdf, expand_aead_key

_AAD_PURPOSE_DATA = 0x01


class CryptoVault:
    """The crate's ``CryptoVault``."""

    def __init__(self, kdf: Argon2Kdf, cipher: Aes256GcmSivCipher, fec: NoFec) -> None:
        """Compose the three strategies."""
        self._kdf = kdf
        self._cipher = cipher
        self._fec = fec

    def decrypt_with_key(self, key: bytes, blob: str) -> str:
        """Decrypt a data blob."""
        received = base64.b64decode(blob)
        version, plaintext_len, body = decode_blob(self._fec, received)
        header = bytes([version]) + struct.pack("<I", plaintext_len)
        aad = bytes([_AAD_PURPOSE_DATA]) + header
        nonce, sealed = body[:NONCE_LEN], body[NONCE_LEN:]
        plaintext = self._cipher.decrypt(expand_aead_key(key), nonce, aad, sealed)
        return plaintext.decode("utf-8")
