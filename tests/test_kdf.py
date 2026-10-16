# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Key derivation: Argon2id master keys and HKDF sub-keys (CV-05, CV-06)."""

from cryptovault.kdf import Argon2Kdf, _hkdf_expand, expand_aead_key
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


def test_aead_subkey_matches_rfc_5869_and_the_crate() -> None:
    # RFC 5869 test case 3 (no salt, empty info): HKDF output is a prefix code,
    # so the 32-byte expansion is the first 32 bytes of the 42-byte OKM.
    okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
    assert _hkdf_expand(bytes([0x0B] * 22), b"").hex() == okm
    for case in load_rust_fixtures()["hkdf"]:
        aead_key = expand_aead_key(bytes.fromhex(case["master"]))
        assert aead_key.hex() == case["aead_key"]
