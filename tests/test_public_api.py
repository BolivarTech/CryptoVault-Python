# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""The package root re-exports the names the crate root exposes."""

import cryptovault

PUBLIC_NAMES = {
    "Aes256GcmSivCipher",
    "Argon2Kdf",
    "AuthenticatedCipher",
    "ConcatenatedFec",
    "CipherError",
    "CryptoVault",
    "CryptoVaultError",
    "EncodingError",
    "ErrorCorrection",
    "ErrorCorrectionError",
    "InvalidInputError",
    "KeyDerivation",
    "KeyDerivationError",
    "NoFec",
    "constant_time_eq",
    "generate_dek",
    "generate_salt",
}


def test_root_exports_the_vault_strategies_errors_and_utilities() -> None:
    assert set(cryptovault.__all__) >= PUBLIC_NAMES
    for name in PUBLIC_NAMES:
        assert getattr(cryptovault, name) is not None
