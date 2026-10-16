# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""The interleavers permute bytes exactly as the crate's do."""

from cryptovault.error import CryptoVaultError
from cryptovault.fec import BlockInterleaver, CsprngLayer, Interleaver
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


def test_csprng_layer_shuffles_as_the_crate_and_inverts() -> None:
    cases = load_rust_fec_fixtures()["csprng_interleave"]
    assert len(cases) == 12
    for case in cases:
        layer = CsprngLayer(bytes.fromhex(case["seed"]))
        stream = bytes.fromhex(case["stream"])
        window = case["window_len"]
        assert layer.interleave(stream, window).hex() == case["interleaved"]
        assert layer.deinterleave(bytes.fromhex(case["interleaved"]), window) == stream


def test_csprng_layer_accepts_only_a_32_byte_seed_as_the_crate() -> None:
    cases = load_rust_fec_fixtures()["csprng_seed"]
    assert [case["seed_len"] for case in cases] == [0, 31, 32, 33]
    for case in cases:
        try:
            CsprngLayer(bytes(case["seed_len"]))
        except CryptoVaultError as error:
            got: dict[str, object] = {"error": str(error)}
        else:
            got = {"ok": None}
        assert got == case["expect"]


def test_interleaver_composes_block_then_csprng_as_the_crate() -> None:
    cases = load_rust_fec_fixtures()["interleaver"]
    assert len(cases) == 6
    for case in cases:
        block = BlockInterleaver(case["depth"])
        seed = case["seed"]
        csprng = None if seed is None else CsprngLayer(bytes.fromhex(seed))
        interleaver = Interleaver(block, csprng)
        stream = bytes.fromhex(case["stream"])
        assert interleaver.interleave(stream).hex() == case["interleaved"]
        assert interleaver.deinterleave(bytes.fromhex(case["interleaved"])) == stream
