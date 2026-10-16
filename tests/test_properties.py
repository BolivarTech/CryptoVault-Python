# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Property-based checks over the whole input space (acceptance criterion 3).

Run longer with ``HYPOTHESIS_PROFILE=milestone`` (more examples, no deadline).
"""

import base64
import contextlib
import os

from hypothesis import given, settings
from hypothesis import strategies as st

from cryptovault import (
    Aes256GcmSivCipher,
    Argon2Kdf,
    CryptoVault,
    CryptoVaultError,
    NoFec,
)

settings.register_profile("milestone", max_examples=5000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

VAULT = CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())
KEYS = st.binary(min_size=32, max_size=32)


@given(key=KEYS, plaintext=st.text(max_size=256), data=st.data())
def test_no_single_bit_flip_of_a_valid_blob_is_accepted(
    key: bytes, plaintext: str, data: st.DataObject
) -> None:
    blob = VAULT.encrypt_with_key(key, plaintext)
    assert VAULT.decrypt_with_key(key, blob) == plaintext
    raw = bytearray(base64.b64decode(blob))
    bit = data.draw(st.integers(min_value=0, max_value=len(raw) * 8 - 1))
    raw[bit // 8] ^= 1 << (bit % 8)
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    try:
        VAULT.decrypt_with_key(key, tampered)
    except CryptoVaultError:
        return
    raise AssertionError(f"bit {bit} flipped and the blob still opened")


DEFAULT_VAULT = CryptoVault.default()


@settings(max_examples=40)
@given(key=KEYS, plaintext=st.text(max_size=64), data=st.data())
def test_a_flipped_bit_under_fec_is_corrected_or_rejected_never_misread(
    key: bytes, plaintext: str, data: st.DataObject
) -> None:
    raw = bytearray(base64.b64decode(DEFAULT_VAULT.encrypt_with_key(key, plaintext)))
    bit = data.draw(st.integers(min_value=0, max_value=len(raw) * 8 - 1))
    raw[bit // 8] ^= 1 << (bit % 8)
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with contextlib.suppress(CryptoVaultError):
        assert DEFAULT_VAULT.decrypt_with_key(key, tampered) == plaintext
