# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Reed-Solomon RS(255, 223) outer code, the crate's ``ReedSolomonCodec``."""

from cryptovault.constants import MAX_BLOB_LEN, RS_BLOCK, RS_DATA, RS_PARITY
from cryptovault.error import ErrorCorrectionError, InvalidInputError
from cryptovault.fec._reedsolomon import (
    ReedSolomon,
    RsInvalidInputError,
    RsUncorrectableError,
)

_RS = ReedSolomon(RS_PARITY, RS_DATA)


class ReedSolomonCodec:
    """Reed-Solomon RS(255, 223) outer code."""

    def encode(self, data: bytes) -> bytes:
        """Encode ``data`` into whole codewords.

        Args:
            data: The bytes to protect.

        Returns:
            The codewords.
        """
        return _RS.encode(data)

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        """Correct up to 16 symbol errors per codeword, then truncate.

        Args:
            encoded: The received codewords.
            pre_len: The data length to recover.

        Returns:
            The recovered data.

        Raises:
            InvalidInputError: If the lengths are inconsistent.
            ErrorCorrectionError: If a codeword cannot be corrected.
        """
        if len(encoded) % RS_BLOCK:
            raise InvalidInputError("malformed blob")
        try:
            return _RS.decode(encoded, pre_len)
        except RsUncorrectableError as exc:
            raise ErrorCorrectionError("forward error correction failed") from exc
        except RsInvalidInputError as exc:
            raise InvalidInputError("malformed blob") from exc

    def validate_pre_fec(self, received: bytes) -> int:
        """Check the framing of an RS-only blob before decoding it.

        Args:
            received: The base64-decoded blob.

        Returns:
            The data length to recover: ``RS_DATA`` per codeword.

        Raises:
            InvalidInputError: If ``received`` is longer than ``MAX_BLOB_LEN``
                or is not one or more whole codewords.
        """
        if len(received) > MAX_BLOB_LEN:
            raise InvalidInputError("input exceeds maximum size")
        blocks, rest = divmod(len(received), RS_BLOCK)
        if rest or blocks < 1:
            raise InvalidInputError("malformed blob")
        return blocks * RS_DATA
