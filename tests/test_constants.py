# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Public constants carry the crate's values, derived limits included (CV-13)."""

import cryptovault
from tests.conftest import load_rust_fec_fixtures, load_rust_fixtures

CONSTANT_NAMES = [
    "KEY_LEN",
    "SALT_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "HEADER_LEN",
    "BLOB_VERSION",
    "MAX_PLAINTEXT_LEN",
    "RECOMMENDED_MAX_PAYLOAD",
    "MAX_BLOB_LEN",
    "MAX_B64_LEN",
    "ARGON2_M_KIB",
    "ARGON2_T",
    "ARGON2_P",
]


def test_every_public_constant_equals_the_crate_value() -> None:
    crate = load_rust_fixtures()["constants"]
    assert sorted(crate) == sorted(CONSTANT_NAMES)
    ours = {name: getattr(cryptovault, name, None) for name in CONSTANT_NAMES}
    assert ours == crate


FEC_CONSTANT_NAMES = [
    "RS_DATA",
    "RS_PARITY",
    "RS_BLOCK",
    "RS_INTERLEAVE_MAX",
    "VITERBI_CHUNK",
    "TERMINATION_OVERHEAD",
]


def test_every_fec_constant_equals_the_crate_value() -> None:
    crate = load_rust_fec_fixtures()["constants"]
    assert sorted(crate) == sorted(FEC_CONSTANT_NAMES)
    ours = {name: getattr(cryptovault, name, None) for name in FEC_CONSTANT_NAMES}
    assert ours == crate
