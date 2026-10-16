# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""AEAD strategy: AES-256-GCM-SIV (RFC 8452) from ``cryptography``."""

from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from cryptovault.error import CipherError

_AUTH_FAILED: Final = "AES-256-GCM-SIV authentication failed"


class Aes256GcmSivCipher:
    """AES-256-GCM-SIV, the crate's ``Aes256GcmSivCipher``.

    Stateless: an instance holds no key and may be shared between threads.
    """

    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        """Encrypt and authenticate ``plaintext`` under ``aad``.

        Args:
            key: The 32-byte AES-256 key.
            nonce: The 12-byte nonce.
            aad: Associated data, authenticated but not encrypted.
            plaintext: The data to encrypt.

        Returns:
            ``ciphertext ‖ tag``, 16 bytes longer than ``plaintext``.
        """
        return AESGCMSIV(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, key: bytes, nonce: bytes, aad: bytes, sealed: bytes) -> bytes:
        """Verify and decrypt ``sealed`` (``ciphertext ‖ tag``).

        Args:
            key: The 32-byte AES-256 key.
            nonce: The 12-byte nonce.
            aad: The associated data the blob was sealed with.
            sealed: ``ciphertext ‖ tag``.

        Returns:
            The plaintext.

        Raises:
            CipherError: If the tag does not verify: wrong key, wrong AAD or
                tampered data. The message does not say which.
        """
        try:
            return AESGCMSIV(key).decrypt(nonce, sealed, aad)
        except InvalidTag as exc:
            raise CipherError(_AUTH_FAILED) from exc
