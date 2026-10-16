# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Vault blobs under every FEC strategy open as they do in the crate."""

from typing import Any

from cryptovault import Aes256GcmSivCipher, Argon2Kdf, CryptoVault
from cryptovault.fec import (
    ConcatenatedFec,
    ErrorCorrection,
    ReedSolomonCodec,
    ViterbiOnlyFec,
)
from tests.conftest import load_rust_fec_fixtures


def fec_from_spec(spec: dict[str, Any]) -> ErrorCorrection:
    """Build the FEC strategy a fixture row names."""
    name = spec["name"]
    if name == "ConcatenatedFec":
        return ConcatenatedFec.default()
    if name == "ViterbiOnlyFec":
        return ViterbiOnlyFec()
    if name == "ReedSolomonCodec":
        return ReedSolomonCodec()
    if name == "CsprngFromMaster":
        master = bytes.fromhex(spec["master"])
        return ConcatenatedFec.with_csprng_from_master(master, spec["depth"])
    raise AssertionError(f"unknown FEC strategy {name}")


def test_every_crate_blob_opens_under_its_fec_strategy() -> None:
    rows = load_rust_fec_fixtures()["vault_blobs"]
    assert len(rows) == 36
    for row in rows:
        vault = CryptoVault(
            Argon2Kdf(), Aes256GcmSivCipher(), fec_from_spec(row["fec"])
        )
        if row["kind"] == "data":
            got = vault.decrypt_with_key(bytes.fromhex(row["key"]), row["blob"])
            assert got == row["plaintext"]
        else:
            material = vault.unwrap_key(
                bytes.fromhex(row["kek"]), bytes.fromhex(row["salt"]), row["blob"]
            )
            assert material.hex() == row["key_material"]


def test_default_vault_opens_the_crate_default_blobs() -> None:
    rows = [
        row
        for row in load_rust_fec_fixtures()["vault_blobs"]
        if row["fec"]["name"] == "ConcatenatedFec" and row["kind"] == "data"
    ]
    assert len(rows) == 5
    vault = CryptoVault.default()
    for row in rows:
        got = vault.decrypt_with_key(bytes.fromhex(row["key"]), row["blob"])
        assert got == row["plaintext"]
