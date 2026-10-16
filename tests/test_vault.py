# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""``CryptoVault`` replicates the crate's vault over ``NoFec`` (CV-01 to CV-11)."""

import base64
import functools
import struct
from collections.abc import Callable

import pytest

from cryptovault.cipher import Aes256GcmSivCipher
from cryptovault.constants import MAX_B64_LEN, MAX_PLAINTEXT_LEN
from cryptovault.error import CryptoVaultError, EncodingError, InvalidInputError
from cryptovault.fec import NoFec
from cryptovault.kdf import Argon2Kdf
from cryptovault.vault import CryptoVault
from tests.conftest import load_rust_fixtures


def make_vault() -> CryptoVault:
    return CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())


def test_every_crate_data_blob_opens_to_its_plaintext() -> None:
    cases = load_rust_fixtures()["data"]
    assert len(cases) == 6
    vault = make_vault()
    for case in cases:
        key = bytes.fromhex(case["key"])
        assert vault.decrypt_with_key(key, case["blob"]) == case["plaintext"]


def outcome_of(call: Callable[[], object]) -> dict[str, object]:
    """Run ``call`` and render its result the way the fixture generator does."""
    try:
        value = call()
    except CryptoVaultError as error:
        return {"error": str(error)}
    return {"ok": value.hex() if isinstance(value, bytes) else value}


def adversarial_mismatches(group: str, expected_count: int) -> list[object]:
    """Replay one group of the crate's adversarial table through ``vault``.

    Returns every case whose outcome differs from the crate's, so a failing
    assertion lists them all at once.
    """
    cases = [c for c in load_rust_fixtures()["adversarial"] if c["group"] == group]
    assert len(cases) == expected_count
    vault = make_vault()
    mismatches: list[object] = []
    for case in cases:
        key = bytes.fromhex(case["key"])
        got = outcome_of(functools.partial(vault.decrypt_with_key, key, case["blob"]))
        if got != case["expect"]:
            mismatches.append((case["label"], got, case["expect"]))
    return mismatches


def test_every_single_bit_flip_fails_exactly_as_in_the_crate() -> None:
    # "hi" makes a 35-byte blob: header 5, nonce 12, ciphertext 2, tag 16.
    assert adversarial_mismatches("bit flip", 35 * 8) == []


def test_only_canonical_padded_base64_is_accepted_as_in_the_crate() -> None:
    assert adversarial_mismatches("encoding", 14) == []


def test_master_key_must_be_exactly_32_bytes_as_in_the_crate() -> None:
    assert adversarial_mismatches("key", 4) == []


def test_non_utf8_plaintext_reports_the_crate_utf8_error() -> None:
    assert adversarial_mismatches("utf8", 9) == []


def test_truncated_padded_and_relabelled_blobs_behave_as_in_the_crate() -> None:
    # 35 truncations, 2 appended tails (ignored, CV-Q6), 3 versions, 5 lengths.
    assert adversarial_mismatches("structure", 35 + 2 + 3 + 5) == []


def test_with_max_blob_len_caps_a_new_vault_as_in_the_crate() -> None:
    cases = load_rust_fixtures()["max_blob_len"]
    assert len(cases) == 4
    original = make_vault()
    for case in cases:
        capped = original.with_max_blob_len(case["cap"])
        assert capped is not original
        key = bytes.fromhex(case["key"])
        got = outcome_of(functools.partial(capped.decrypt_with_key, key, case["blob"]))
        assert got == case["expect"], case["cap"]
        assert original.decrypt_with_key(key, case["blob"]) == "hi"


@pytest.mark.parametrize(
    "blob",
    [
        # Over MAX_B64_LEN: rejected on length before the bad alphabet is seen.
        "!" * (MAX_B64_LEN + 1),
        # Under MAX_B64_LEN characters but over it in UTF-8 bytes, as Rust counts.
        "é" * (MAX_B64_LEN // 2 + 1),
        # Valid base64 of MAX_B64_LEN characters decodes to more than MAX_BLOB_LEN.
        "A" * MAX_B64_LEN,
    ],
    ids=["base64-too-long", "utf8-bytes-too-long", "decoded-too-long"],
)
def test_oversized_input_is_rejected_before_decryption(blob: str) -> None:
    with pytest.raises(InvalidInputError) as caught:
        make_vault().decrypt_with_key(bytes(32), blob)
    assert str(caught.value) == "Invalid input: input exceeds maximum size"


@pytest.mark.parametrize(
    "plaintext", ["", "a", "sk-secret", "ñandú \U0001f510", "x" * 1000]
)
def test_encrypt_produces_a_fresh_blob_in_the_crate_layout(plaintext: str) -> None:
    vault, key = make_vault(), bytes(range(32))
    blob = vault.encrypt_with_key(key, plaintext)
    other = vault.encrypt_with_key(key, plaintext)
    assert blob != other  # fresh random nonce per message
    raw = base64.b64decode(blob, validate=True)
    encoded = plaintext.encode("utf-8")
    assert raw[:5] == b"\x01" + struct.pack("<I", len(encoded))
    assert len(raw) == 5 + 12 + len(encoded) + 16
    assert vault.decrypt_with_key(key, blob) == plaintext


@pytest.mark.parametrize(
    ("key", "plaintext", "error"),
    [
        (bytes(31), "hi", InvalidInputError("master key must be exactly 32 bytes")),
        (bytes(33), "hi", InvalidInputError("master key must be exactly 32 bytes")),
        (
            bytes(32),
            "x" * (MAX_PLAINTEXT_LEN + 1),
            InvalidInputError("plaintext exceeds maximum size"),
        ),
        # Counted in UTF-8 bytes: 5 Mi + 1 two-byte characters exceed 10 MiB.
        (
            bytes(32),
            "é" * (MAX_PLAINTEXT_LEN // 2 + 1),
            InvalidInputError("plaintext exceeds maximum size"),
        ),
        (
            bytes(32),
            "lone \ud800 surrogate",
            EncodingError("plaintext is not valid UTF-8"),
        ),
        # The key is checked first, as in the crate.
        (bytes(31), "\ud800", InvalidInputError("master key must be exactly 32 bytes")),
    ],
    ids=["key-31", "key-33", "too-long", "too-long-utf8", "surrogate", "key-first"],
)
def test_encrypt_rejects_invalid_input_before_encrypting(
    key: bytes, plaintext: str, error: CryptoVaultError
) -> None:
    with pytest.raises(CryptoVaultError) as caught:
        make_vault().encrypt_with_key(key, plaintext)
    assert type(caught.value) is type(error)
    assert caught.value.message == error.message


def test_derive_key_matches_the_crate_including_its_errors() -> None:
    cases = load_rust_fixtures()["derive"]
    assert len(cases) == 7
    vault = make_vault()
    for case in cases:
        salt = bytes.fromhex(case["salt"])
        got = outcome_of(functools.partial(vault.derive_key, case["password"], salt))
        assert got == case["expect"], case


def test_derive_key_rejects_a_password_that_is_not_encodable_as_utf8() -> None:
    with pytest.raises(EncodingError) as caught:
        make_vault().derive_key("pass\ud800word", bytes(16))
    assert caught.value.message == "password is not valid UTF-8"


def test_every_crate_wrapped_key_unwraps_with_its_kek_and_salt() -> None:
    cases = load_rust_fixtures()["envelope"]
    assert len(cases) == 4
    vault = make_vault()
    for case in cases:
        kek, salt = bytes.fromhex(case["kek"]), bytes.fromhex(case["salt"])
        assert vault.unwrap_key(kek, salt, case["blob"]).hex() == case["key_material"]


def test_envelope_binds_salt_and_purpose_as_in_the_crate() -> None:
    cases = [c for c in load_rust_fixtures()["adversarial"] if c["group"] == "envelope"]
    assert len(cases) == 6
    vault = make_vault()
    mismatches = []
    for case in cases:
        key = bytes.fromhex(case["key"])
        call: Callable[[], object]
        if case["op"] == "unwrap":
            salt = bytes.fromhex(case["salt"])
            call = functools.partial(vault.unwrap_key, key, salt, case["blob"])
        else:
            call = functools.partial(vault.decrypt_with_key, key, case["blob"])
        got = outcome_of(call)
        if got != case["expect"]:
            mismatches.append((case["label"], got, case["expect"]))
    assert mismatches == []
