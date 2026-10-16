# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Blob wire layout and the structural checks made before decryption.

Private, as in the crate: the public doors are the vault's methods. Layout::

    protected = version (1) ‖ plaintext_len (u32 LE, 4) ‖ nonce ‖ ciphertext ‖ tag
    blob      = fec.encode(protected)

Every rejection uses a fixed message that repeats nothing of the input.
"""

import struct
from typing import Final

from cryptovault.constants import (
    BLOB_VERSION,
    HEADER_LEN,
    MAX_PLAINTEXT_LEN,
    NONCE_LEN,
    TAG_LEN,
)
from cryptovault.error import InvalidInputError
from cryptovault.fec import ErrorCorrection

_MALFORMED: Final = "malformed blob"
_LEN_FIELD: Final = struct.Struct("<I")


def decode_blob(fec: ErrorCorrection, received: bytes) -> tuple[int, int, bytes]:
    """Undo the FEC layer and split the protected payload, checking structure.

    Checks run in the crate's order: the FEC length gate, then the header
    length, the version, the declared plaintext length against
    ``MAX_PLAINTEXT_LEN``, and that length against the bytes received. Bytes
    after the tag are ignored, as in the crate.

    Args:
        fec: The strategy that encoded the blob.
        received: The base64-decoded blob.

    Returns:
        ``(version, plaintext_len, body)`` with ``body = nonce ‖ ciphertext ‖ tag``.

    Raises:
        InvalidInputError: ``"malformed blob"`` for a short or inconsistent blob,
            ``"unsupported blob version"`` for a version other than 1, or the
            FEC strategy's own rejection.
    """
    protected = fec.decode(received, fec.validate_pre_fec(received))
    if len(protected) < HEADER_LEN:
        raise InvalidInputError(_MALFORMED)
    version = protected[0]
    if version != BLOB_VERSION:
        raise InvalidInputError("unsupported blob version")
    (plaintext_len,) = _LEN_FIELD.unpack_from(protected, 1)
    if plaintext_len > MAX_PLAINTEXT_LEN:
        raise InvalidInputError(_MALFORMED)
    protected_len = HEADER_LEN + NONCE_LEN + plaintext_len + TAG_LEN
    if protected_len > len(protected):
        raise InvalidInputError(_MALFORMED)
    return version, plaintext_len, protected[HEADER_LEN:protected_len]
