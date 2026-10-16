# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Key derivation: Argon2id master keys and HKDF sub-keys (CV-05, CV-06)."""

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

from cryptovault import kdf as kdf_module
from cryptovault.error import KeyDerivationError
from cryptovault.kdf import (
    Argon2Kdf,
    _hkdf_expand,
    expand_aead_key,
    expand_interleaver_seed,
)
from tests.conftest import load_rust_fec_fixtures, load_rust_fixtures


def test_argon2id_backend_failure_is_a_key_derivation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unsupported(**params: object) -> None:
        raise UnsupportedAlgorithm("Argon2id is not supported by this OpenSSL")

    monkeypatch.setattr(kdf_module, "Argon2id", unsupported)
    with pytest.raises(KeyDerivationError) as caught:
        Argon2Kdf().derive_master(b"pw", bytes(16))
    assert caught.value.message.startswith("Argon2id derivation failed: ")
    assert isinstance(caught.value.__cause__, UnsupportedAlgorithm)


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


def test_interleaver_seed_matches_the_crate_and_differs_from_the_aead_key() -> None:
    cases = load_rust_fec_fixtures()["interleaver_seed"]
    assert len(cases) == 3
    for case in cases:
        master = bytes.fromhex(case["master"])
        seed = expand_interleaver_seed(master)
        assert seed.hex() == case["seed"]
        assert seed != expand_aead_key(master)
