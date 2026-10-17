# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Reed-Solomon RS(255, 223) outer code, the crate's ``ReedSolomonCodec``."""

from cryptovault.constants import MAX_BLOB_LEN, RS_BLOCK, RS_DATA
from cryptovault.error import ErrorCorrectionError, InvalidInputError
from cryptovault.fec import _codecs
from cryptovault.fec._reedsolomon import RsInvalidInputError, RsUncorrectableError


class ReedSolomonCodec:
    """Reed-Solomon RS(255, 223) outer code, usable alone as an FEC strategy.

    Each 223-byte data chunk becomes a 255-byte codeword with 32 parity bytes,
    the last chunk zero-padded; a codeword corrects up to 16 bad bytes. The
    field and code follow the ``reedsolomon`` 0.2.0 crate the Rust side uses
    (polynomial ``0x187``, first root ``alpha^112``), and decoding refuses to
    return a codeword whose syndromes are not all zero. Stateless and
    shareable between threads.

    Example:
        >>> codec = ReedSolomonCodec()
        >>> encoded = bytearray(codec.encode(b"payload"))
        >>> encoded[0] ^= 0xFF
        >>> codec.decode(bytes(encoded), 7)
        b'payload'
    """

    def encode(self, data: bytes) -> bytes:
        """Encode ``data`` into whole codewords.

        Args:
            data: The bytes to protect.

        Returns:
            The codewords.
        """
        return _codecs.ACTIVE.rs_encode(data)

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
            return _codecs.ACTIVE.rs_decode(encoded, pre_len)
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
