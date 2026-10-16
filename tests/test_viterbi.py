# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""``ViterbiCodec`` reproduces the crate's chunked CCSDS K=7 R=1/2 code."""

import hashlib

from cryptovault.fec import ViterbiCodec
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
