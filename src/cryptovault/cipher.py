# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""AEAD strategy: AES-256-GCM-SIV (RFC 8452) from ``cryptography``."""

from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from cryptovault.constants import KEY_LEN, NONCE_LEN
from cryptovault.error import CipherError

_AUTH_FAILED: Final = "AES-256-GCM-SIV authentication failed"


class Aes256GcmSivCipher:
    """AES-256-GCM-SIV, the crate's ``Aes256GcmSivCipher``.

    Stateless: an instance holds no key and may be shared between threads.
    """

    @staticmethod
    def _aead_for(key: bytes, nonce: bytes) -> AESGCMSIV:
        """Check the key and nonce lengths, then build the primitive.

        The key is checked first, as in the crate. ``cryptography`` would accept
        a 16- or 24-byte key and silently run AES-128 or AES-192.

        Raises:
            CipherError: If the key is not 32 bytes or the nonce not 12.
        """
        if len(key) != KEY_LEN:
            raise CipherError(f"AES-256 key must be {KEY_LEN} bytes, got {len(key)}")
        if len(nonce) != NONCE_LEN:
            raise CipherError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
        return AESGCMSIV(key)

    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        """Encrypt and authenticate ``plaintext`` under ``aad``.

        Args:
            key: The 32-byte AES-256 key.
            nonce: The 12-byte nonce.
            aad: Associated data, authenticated but not encrypted.
            plaintext: The data to encrypt.

        Returns:
            ``ciphertext ‖ tag``, 16 bytes longer than ``plaintext``.

        Raises:
            CipherError: If the key is not 32 bytes or the nonce not 12.
        """
        return self._aead_for(key, nonce).encrypt(nonce, plaintext, aad)

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
            CipherError: If the key is not 32 bytes, the nonce not 12, or the
                tag does not verify (wrong key, wrong AAD or tampered data; the
                message does not say which).
        """
        aead = self._aead_for(key, nonce)
        try:
            return aead.decrypt(nonce, sealed, aad)
        except InvalidTag as exc:
            raise CipherError(_AUTH_FAILED) from exc
