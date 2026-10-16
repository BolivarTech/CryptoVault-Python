# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""``ReedSolomonCodec`` reproduces the crate's RS(255, 223) outer code."""

from cryptovault.fec import ReedSolomonCodec
from tests.conftest import load_rust_fec_fixtures


def test_rs_encode_matches_the_crate_codewords() -> None:
    cases = load_rust_fec_fixtures()["rs_encode"]
    assert len(cases) == 7
    codec = ReedSolomonCodec()
    for case in cases:
        encoded = codec.encode(bytes.fromhex(case["data"]))
        assert encoded.hex() == case["encoded"]
