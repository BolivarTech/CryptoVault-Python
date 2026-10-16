# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""The vault: composes key derivation, AEAD and FEC strategies."""

import base64
import struct

from cryptovault.cipher import Aes256GcmSivCipher
from cryptovault.constants import HEADER_LEN, NONCE_LEN, TAG_LEN
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
        protected = self._fec.decode(received, self._fec.validate_pre_fec(received))
        (plaintext_len,) = struct.unpack_from("<I", protected, 1)
        header = protected[:HEADER_LEN]
        body = protected[HEADER_LEN : HEADER_LEN + NONCE_LEN + plaintext_len + TAG_LEN]
        aad = bytes([_AAD_PURPOSE_DATA]) + header
        nonce, sealed = body[:NONCE_LEN], body[NONCE_LEN:]
        plaintext = self._cipher.decrypt(expand_aead_key(key), nonce, aad, sealed)
        return plaintext.decode("utf-8")
