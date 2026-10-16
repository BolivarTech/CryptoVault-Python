# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Typed error domain: one exception class per ``CryptoError`` variant.

Every failure the package reports is a :class:`CryptoVaultError`. The subclass
names the stage that failed, so a caller can tell a structural rejection from a
failed authentication tag; the message stays generic and never repeats the
caller's input. ``str(error)`` matches the ``Display`` output of the Rust crate
for the same failure, prefix included.

Example:
    >>> from cryptovault.error import CipherError, CryptoVaultError
    >>> error = CipherError("AES-256-GCM-SIV authentication failed")
    >>> str(error)
    'Cipher error: AES-256-GCM-SIV authentication failed'
    >>> isinstance(error, CryptoVaultError)
    True
"""

from typing import ClassVar


class CryptoVaultError(Exception):
    """Base of every error the package raises.

    Subclasses set ``PREFIX``, the stage label the crate prints before the
    message. Catch this class to handle every failure of the package at once.

    Args:
        message: The fixed, oracle-free description of the failure.

    Attributes:
        message: The description without the stage prefix.
    """

    PREFIX: ClassVar[str] = "CryptoVault error"

    def __init__(self, message: str) -> None:
        """Store the message and pass it to :class:`Exception`."""
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        """Return ``"<PREFIX>: <message>"``, the crate's ``Display`` form."""
        return f"{self.PREFIX}: {self.message}"


class KeyDerivationError(CryptoVaultError):
    """Argon2id or HKDF failure, or no entropy for a salt or DEK."""

    PREFIX = "Key derivation error"


class CipherError(CryptoVaultError):
    """AEAD failure: a tag that does not verify, or no entropy for a nonce."""

    PREFIX = "Cipher error"


class ErrorCorrectionError(CryptoVaultError):
    """Corruption beyond the capacity of a forward-error-correction codec."""

    PREFIX = "Error correction error"


class EncodingError(CryptoVaultError):
    """Non-canonical base64, or text that is not valid UTF-8."""

    PREFIX = "Encoding error"


class InvalidInputError(CryptoVaultError):
    """Structural or input-validation failure, raised before any decryption."""

    PREFIX = "Invalid input"
