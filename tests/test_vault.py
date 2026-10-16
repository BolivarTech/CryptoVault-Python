# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""``CryptoVault`` replicates the crate's vault over ``NoFec`` (CV-01 to CV-11)."""

from cryptovault.cipher import Aes256GcmSivCipher
from cryptovault.fec import NoFec
from cryptovault.kdf import Argon2Kdf
from cryptovault.vault import CryptoVault
from tests.conftest import load_rust_fixtures


def make_vault() -> CryptoVault:
    return CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())


def test_every_crate_data_blob_opens_to_its_plaintext() -> None:
    cases = load_rust_fixtures()["data"]
    assert len(cases) == 6
    vault = make_vault()
    for case in cases:
        key = bytes.fromhex(case["key"])
        assert vault.decrypt_with_key(key, case["blob"]) == case["plaintext"]
