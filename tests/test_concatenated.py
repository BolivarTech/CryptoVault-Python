# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""``ConcatenatedFec`` composes RS, interleaver and Viterbi as the crate does."""

import hashlib
from typing import Any

from cryptovault.error import CryptoVaultError
from cryptovault.fec import (
    BlockInterleaver,
    ConcatenatedFec,
    CsprngLayer,
    Interleaver,
    ReedSolomonCodec,
    ViterbiCodec,
)
from tests.conftest import load_rust_fec_fixtures


def _stack(spec: dict[str, Any]) -> ConcatenatedFec:
    seed = spec["seed"]
    csprng = None if seed is None else CsprngLayer(bytes.fromhex(seed))
    interleaver = Interleaver(BlockInterleaver(spec["depth"]), csprng)
    return ConcatenatedFec(ReedSolomonCodec(), interleaver, ViterbiCodec())


def test_concatenated_fec_encodes_corrects_and_fails_as_the_crate() -> None:
    cases = load_rust_fec_fixtures()["concatenated"]
    assert len(cases) == 12
    for case in cases:
        fec = _stack(case["stack"])
        received = bytes.fromhex(case["received"])
        got: dict[str, object] = {}
        try:
            got["validate"] = fec.validate_pre_fec(received)
        except CryptoVaultError as error:
            got["validate"] = str(error)
        try:
            decoded = fec.decode(received, case["pre_len"])
        except CryptoVaultError as error:
            got["decode"] = str(error)
        else:
            got["decode"] = hashlib.sha256(decoded).hexdigest()
        if "data" in case:
            got["encode"] = fec.encode(bytes.fromhex(case["data"])) == received
        assert got == case["expect"], case["label"]


def test_default_stack_encodes_as_the_crate_default() -> None:
    cases = load_rust_fec_fixtures()["concatenated_default"]
    assert len(cases) == 3
    for case in cases:
        encoded = ConcatenatedFec.default().encode(bytes.fromhex(case["data"]))
        assert hashlib.sha256(encoded).hexdigest() == case["encoded_sha256"]


def test_csprng_stack_from_master_matches_the_crate_and_its_errors() -> None:
    cases = load_rust_fec_fixtures()["concatenated_from_master"]
    assert len(cases) == 6
    for case in cases:
        try:
            fec = ConcatenatedFec.with_csprng_from_master(
                bytes.fromhex(case["master"]), case["depth"]
            )
        except CryptoVaultError as error:
            got = str(error)
        else:
            encoded = fec.encode(bytes.fromhex(case["data"]))
            got = hashlib.sha256(encoded).hexdigest()
        assert got == case["expect"], case["label"]
