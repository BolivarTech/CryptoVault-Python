# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""``ReedSolomonCodec`` reproduces the crate's RS(255, 223) outer code."""

from cryptovault.error import CryptoVaultError
from cryptovault.fec import ReedSolomonCodec
from tests.conftest import load_rust_fec_fixtures


def test_rs_encode_matches_the_crate_codewords() -> None:
    cases = load_rust_fec_fixtures()["rs_encode"]
    assert len(cases) == 7
    codec = ReedSolomonCodec()
    for case in cases:
        encoded = codec.encode(bytes.fromhex(case["data"]))
        assert encoded.hex() == case["encoded"]


def test_rs_decode_corrects_and_fails_exactly_as_the_crate() -> None:
    cases = load_rust_fec_fixtures()["rs_decode"]
    assert len(cases) == 146
    codec = ReedSolomonCodec()
    for case in cases:
        try:
            decoded = codec.decode(bytes.fromhex(case["encoded"]), case["pre_len"])
        except CryptoVaultError as error:
            got = {"error": str(error)}
        else:
            got = {"ok": decoded.hex()}
        assert got == case["expect"], case["label"]
