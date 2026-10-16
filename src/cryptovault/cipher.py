# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""AEAD strategy: AES-256-GCM-SIV (RFC 8452) from ``cryptography``."""

import os
from typing import Final, Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from cryptovault.constants import KEY_LEN, NONCE_LEN
from cryptovault.error import CipherError

_AUTH_FAILED: Final = "AES-256-GCM-SIV authentication failed"


def sample_nonce() -> bytes:
    """Draw a fresh random nonce from the operating-system CSPRNG.

    Every message gets its own nonce; a counter or a fixed nonce is never used.

    Returns:
        ``NONCE_LEN`` (12) random bytes.

    Raises:
        CipherError: If the operating system cannot supply entropy. Weak bytes
            are never returned instead.
    """
    try:
        return os.urandom(NONCE_LEN)
    except OSError as exc:
        raise CipherError(f"OsRng nonce sampling failed: {exc}") from exc


@runtime_checkable
class AuthenticatedCipher(Protocol):
    """AEAD strategy, the crate's ``AuthenticatedCipher`` trait."""

    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        """Encrypt and authenticate ``plaintext`` under ``aad``.

        Args:
            key: The AEAD key.
            nonce: The per-message nonce.
            aad: Associated data, authenticated but not encrypted.
            plaintext: The data to encrypt.

        Returns:
            ``ciphertext ‖ tag``.

        Raises:
            CipherError: If the key or nonce is invalid.
        """
        ...

    def decrypt(self, key: bytes, nonce: bytes, aad: bytes, sealed: bytes) -> bytes:
        """Verify and decrypt ``ciphertext ‖ tag``.

        Args:
            key: The AEAD key.
            nonce: The per-message nonce.
            aad: The associated data the blob was sealed with.
            sealed: ``ciphertext ‖ tag``.

        Returns:
            The plaintext.

        Raises:
            CipherError: If the tag does not verify or the inputs are invalid.
        """
        ...


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
            CipherError: If the key is not 32 bytes, the nonce not 12, or the
                OpenSSL backend has no AES-GCM-SIV (it needs OpenSSL 3.2+).
        """
        if len(key) != KEY_LEN:
            raise CipherError(f"AES-256 key must be {KEY_LEN} bytes, got {len(key)}")
        if len(nonce) != NONCE_LEN:
            raise CipherError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
        try:
            return AESGCMSIV(key)
        except UnsupportedAlgorithm as exc:
            raise CipherError(f"AES-256-GCM-SIV is unavailable: {exc}") from exc

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
