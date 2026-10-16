# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""``NoFec`` is the crate's identity codec (CV-04)."""

import pytest

from cryptovault.constants import MAX_BLOB_LEN
from cryptovault.error import InvalidInputError
from cryptovault.fec import NoFec


@pytest.mark.parametrize(
    ("encoded", "pre_len", "decoded"),
    [
        (b"abcdef", 6, b"abcdef"),
        (b"abcdef", 3, b"abc"),
        (b"abcdef", 0, b""),
        (b"abcdef", 99, b"abcdef"),
        (b"", 5, b""),
    ],
)
def test_nofec_encodes_as_identity_and_decodes_by_truncating(
    encoded: bytes, pre_len: int, decoded: bytes
) -> None:
    fec = NoFec()
    assert fec.encode(encoded) == encoded
    assert fec.decode(encoded, pre_len) == decoded
    assert fec.validate_pre_fec(encoded) == len(encoded)
    assert fec.validate_pre_fec(bytes(MAX_BLOB_LEN)) == MAX_BLOB_LEN
    with pytest.raises(InvalidInputError) as caught:
        fec.validate_pre_fec(bytes(MAX_BLOB_LEN + 1))
    assert caught.value.message == "input exceeds maximum size"
