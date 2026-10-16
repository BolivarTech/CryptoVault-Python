# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""The interleavers permute bytes exactly as the crate's do."""

from cryptovault.fec import BlockInterleaver
from tests.conftest import load_rust_fec_fixtures


def test_block_interleaver_permutes_as_the_crate_and_inverts() -> None:
    cases = load_rust_fec_fixtures()["block_interleave"]
    assert len(cases) == 24
    for case in cases:
        interleaver = BlockInterleaver(case["depth"])
        stream = bytes.fromhex(case["stream"])
        assert interleaver.interleave(stream).hex() == case["interleaved"]
        assert interleaver.deinterleave(bytes.fromhex(case["interleaved"])) == stream
