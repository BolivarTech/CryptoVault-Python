# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""The typed error domain mirrors the crate's ``CryptoError`` enum (CV-14)."""

import pytest

from cryptovault.error import (
    CipherError,
    CryptoVaultError,
    EncodingError,
    ErrorCorrectionError,
    InvalidInputError,
    KeyDerivationError,
)

DISPLAY_CASES = [
    (KeyDerivationError, "k", "Key derivation error: k"),
    (CipherError, "c", "Cipher error: c"),
    (ErrorCorrectionError, "e", "Error correction error: e"),
    (EncodingError, "b", "Encoding error: b"),
    (InvalidInputError, "i", "Invalid input: i"),
]


@pytest.mark.parametrize(("error_type", "message", "expected"), DISPLAY_CASES)
def test_every_variant_displays_like_the_crate_and_keeps_its_message(
    error_type: type[CryptoVaultError], message: str, expected: str
) -> None:
    error = error_type(message)
    assert str(error) == expected
    assert error.message == message
    assert isinstance(error, CryptoVaultError)
