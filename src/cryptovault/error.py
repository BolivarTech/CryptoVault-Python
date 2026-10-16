# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Typed error domain: one exception class per ``CryptoError`` variant."""


class CryptoVaultError(Exception):
    """Base of every error the package raises."""

    message: str


class KeyDerivationError(CryptoVaultError):
    """Key-derivation failure."""


class CipherError(CryptoVaultError):
    """AEAD failure."""


class ErrorCorrectionError(CryptoVaultError):
    """Forward-error-correction failure."""


class EncodingError(CryptoVaultError):
    """Encoding failure."""


class InvalidInputError(CryptoVaultError):
    """Structural or input-validation failure."""
