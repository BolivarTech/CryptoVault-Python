# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""``CryptoVault`` replicates the crate's vault over ``NoFec`` (CV-01 to CV-11)."""

import functools
from collections.abc import Callable

from cryptovault.cipher import Aes256GcmSivCipher
from cryptovault.error import CryptoVaultError
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


def outcome_of(call: Callable[[], object]) -> dict[str, object]:
    """Run ``call`` and render its result the way the fixture generator does."""
    try:
        value = call()
    except CryptoVaultError as error:
        return {"error": str(error)}
    return {"ok": value.hex() if isinstance(value, bytes) else value}


def adversarial_mismatches(group: str, expected_count: int) -> list[object]:
    """Replay one group of the crate's adversarial table through ``vault``.

    Returns every case whose outcome differs from the crate's, so a failing
    assertion lists them all at once.
    """
    cases = [c for c in load_rust_fixtures()["adversarial"] if c["group"] == group]
    assert len(cases) == expected_count
    vault = make_vault()
    mismatches: list[object] = []
    for case in cases:
        key = bytes.fromhex(case["key"])
        got = outcome_of(functools.partial(vault.decrypt_with_key, key, case["blob"]))
        if got != case["expect"]:
            mismatches.append((case["label"], got, case["expect"]))
    return mismatches


def test_every_single_bit_flip_fails_exactly_as_in_the_crate() -> None:
    # "hi" makes a 35-byte blob: header 5, nonce 12, ciphertext 2, tag 16.
    assert adversarial_mismatches("bit flip", 35 * 8) == []
