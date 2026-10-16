# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""``ViterbiCodec`` reproduces the crate's chunked CCSDS K=7 R=1/2 code."""

import hashlib

import pytest

from cryptovault.error import CryptoVaultError
from cryptovault.fec import ViterbiCodec, _viterbi
from tests.conftest import load_rust_fec_fixtures


def test_viterbi_encode_matches_the_crate_including_chunking() -> None:
    cases = load_rust_fec_fixtures()["viterbi_encode"]
    assert [case["stream_len"] for case in cases] == [0, 1, 33, 255, 1275, 125205]
    codec = ViterbiCodec()
    for case in cases:
        stream = bytes.fromhex(case["stream"])
        encoded = codec.encode(stream)
        assert len(encoded) == case["encoded_len"]
        assert hashlib.sha256(encoded).hexdigest() == case["encoded_sha256"]


def test_viterbi_decode_recovers_and_miscorrects_exactly_as_the_crate() -> None:
    cases = load_rust_fec_fixtures()["viterbi_decode"]
    assert len(cases) == 26
    codec = ViterbiCodec()
    for case in cases:
        try:
            decoded = codec.decode(bytes.fromhex(case["body"]))
        except CryptoVaultError as error:
            got: dict[str, object] = {"error": str(error)}
        else:
            got = {
                "ok_len": len(decoded),
                "ok_sha256": hashlib.sha256(decoded).hexdigest(),
            }
        assert got == case["expect"], case["label"]


def test_clean_viterbi_body_decodes_without_the_trellis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A full trellis pass costs about 12 us per stage in CPython, about 12 s
    # for one full sub-block; an exact codeword must take the direct path.
    def no_trellis(symbols: list[int], stages: int) -> bytes:
        raise AssertionError("the trellis ran on a clean body")

    monkeypatch.setattr(_viterbi, "_trellis_decode", no_trellis)
    stream = bytes(range(256)) * 600
    assert ViterbiCodec().decode(ViterbiCodec().encode(stream)) == stream
