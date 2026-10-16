# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""The interleavers permute bytes exactly as the crate's do."""

from cryptovault.error import CryptoVaultError
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


def test_block_interleaver_accepts_only_the_crate_depth_range() -> None:
    cases = load_rust_fec_fixtures()["interleaver_depth"]
    assert [case["depth"] for case in cases] == [0, 1, 16, 17, 1000]
    for case in cases:
        try:
            got: dict[str, object] = {"ok": BlockInterleaver(case["depth"]).depth}
        except CryptoVaultError as error:
            got = {"error": str(error)}
        assert got == case["expect"]
