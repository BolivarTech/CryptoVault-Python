# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Viterbi inner code, the crate's ``ViterbiCodec`` and ``ViterbiOnlyFec``."""

from typing import Final

from cryptovault.constants import MAX_BLOB_LEN, TERMINATION_OVERHEAD, VITERBI_CHUNK
from cryptovault.error import InvalidInputError
from cryptovault.fec import _viterbi

_FULL_CHUNK_BODY: Final = 2 * VITERBI_CHUNK + TERMINATION_OVERHEAD
"""Coded length of a full sub-block."""

_MIN_CHUNK_BODY: Final = 2 + TERMINATION_OVERHEAD
"""Coded length of the smallest sub-block, one info byte."""


class ViterbiCodec:
    """CCSDS K=7 R=1/2 hard-decision convolutional code, chunked."""

    def encode(self, rs_stream: bytes) -> bytes:
        """Encode ``rs_stream`` in ``VITERBI_CHUNK``-byte sub-blocks.

        Args:
            rs_stream: The interleaved Reed-Solomon stream.

        Returns:
            The coded stream.
        """
        return b"".join(
            _viterbi.encode(rs_stream[start : start + VITERBI_CHUNK])
            for start in range(0, len(rs_stream), VITERBI_CHUNK)
        )

    def decode(self, blob_body: bytes) -> bytes:
        """Decode ``blob_body``, inverting :meth:`encode`.

        Args:
            blob_body: The received coded stream.

        Returns:
            The recovered Reed-Solomon stream.

        Raises:
            InvalidInputError: If the length cannot be a chunked coded body.
        """
        out = bytearray()
        offset = 0
        for body_len in _chunk_body_lengths(len(blob_body)):
            out += _viterbi.decode(blob_body[offset : offset + body_len])
            offset += body_len
        return bytes(out)


def _chunk_body_lengths(total: int) -> list[int]:
    """Split a coded body into its sub-block lengths.

    Every sub-block but the last is ``2 * VITERBI_CHUNK + 2`` bytes; the last
    must be an even length of at least 4.

    Raises:
        InvalidInputError: If the remainder is not a valid sub-block.
    """
    full, rest = divmod(total, _FULL_CHUNK_BODY)
    bodies = [_FULL_CHUNK_BODY] * full
    if rest:
        if rest < _MIN_CHUNK_BODY or rest % 2:
            raise InvalidInputError("malformed blob")
        bodies.append(rest)
    return bodies


class ViterbiOnlyFec:
    """AEAD plus Viterbi only: no Reed-Solomon and no interleaver."""

    def encode(self, data: bytes) -> bytes:
        """Viterbi-encode the protected payload.

        Args:
            data: The protected payload.

        Returns:
            The coded blob body.
        """
        return ViterbiCodec().encode(data)

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        """Viterbi-decode, then truncate to ``pre_len`` bytes.

        Args:
            encoded: The received coded body.
            pre_len: The payload length to keep.

        Returns:
            The recovered payload, at most ``pre_len`` bytes.

        Raises:
            InvalidInputError: If the length cannot be a chunked coded body.
        """
        return ViterbiCodec().decode(encoded)[:pre_len]

    def validate_pre_fec(self, received: bytes) -> int:
        """Check the framing before decoding.

        Args:
            received: The base64-decoded blob.

        Returns:
            The payload length the body decodes to.

        Raises:
            InvalidInputError: If ``received`` is longer than ``MAX_BLOB_LEN``
                or cannot be a chunked coded body.
        """
        if len(received) > MAX_BLOB_LEN:
            raise InvalidInputError("input exceeds maximum size")
        return _rs_len_from_body(len(received))


def _rs_len_from_body(body_len: int) -> int:
    """Return the info length a chunked coded body of ``body_len`` bytes carries.

    Raises:
        InvalidInputError: If ``body_len`` cannot be a chunked coded body.
    """
    return sum(body // 2 - 1 for body in _chunk_body_lengths(body_len))
