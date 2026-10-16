# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Key derivation: Argon2id master keys and HKDF sub-keys (CV-05, CV-06)."""

from cryptovault.kdf import Argon2Kdf
from tests.conftest import load_rust_fixtures


def test_argon2id_master_key_matches_the_crate_for_every_valid_input() -> None:
    cases = [c for c in load_rust_fixtures()["derive"] if "ok" in c["expect"]]
    assert len(cases) == 3
    kdf = Argon2Kdf()
    for case in cases:
        master = kdf.derive_master(
            case["password"].encode("utf-8"), bytes.fromhex(case["salt"])
        )
        assert master.hex() == case["expect"]["ok"]
