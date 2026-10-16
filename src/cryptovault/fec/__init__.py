# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Forward-error-correction strategies.

The FEC layer only adds channel resilience; confidentiality and integrity come
from the AEAD, applied first. A blob decodes only with the strategy that
encoded it. This stage ships :class:`NoFec`, the identity codec; the crate's
Reed-Solomon, interleaver and Viterbi codecs come in a later stage.
"""

from typing import Final, Protocol

from cryptovault.constants import KEY_LEN, MAX_BLOB_LEN, RS_BLOCK, RS_DATA
from cryptovault.error import InvalidInputError
from cryptovault.fec.interleaver import BlockInterleaver, CsprngLayer, Interleaver
from cryptovault.fec.rs import ReedSolomonCodec
from cryptovault.fec.viterbi import ViterbiCodec, ViterbiOnlyFec, _rs_len_from_body
from cryptovault.kdf import expand_interleaver_seed

_DEFAULT_INTERLEAVE_DEPTH: Final = 5
"""Interleave depth of the default stack, the CCSDS baseline."""

__all__ = [
    "BlockInterleaver",
    "ConcatenatedFec",
    "CsprngLayer",
    "ErrorCorrection",
    "Interleaver",
    "NoFec",
    "ReedSolomonCodec",
    "ViterbiCodec",
    "ViterbiOnlyFec",
]


class ErrorCorrection(Protocol):
    """Forward-error-correction strategy, the crate's ``ErrorCorrection`` trait.

    Implementations must be stateless or thread-safe: one vault may serve
    several threads at once.
    """

    def encode(self, data: bytes) -> bytes:
        """Add redundancy to the protected payload.

        Args:
            data: ``header ‖ nonce ‖ ciphertext ‖ tag``.

        Returns:
            The bytes that go on the wire, before base64.
        """
        ...

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        """Correct errors, then truncate to ``pre_len`` bytes.

        Args:
            encoded: The received bytes.
            pre_len: The payload length returned by :meth:`validate_pre_fec`.

        Returns:
            The recovered protected payload.

        Raises:
            ErrorCorrectionError: If the corruption exceeds the code's capacity.
        """
        ...

    def validate_pre_fec(self, received: bytes) -> int:
        """Check the received length before any decoding allocates memory.

        Args:
            received: The base64-decoded blob.

        Returns:
            The length of the payload :meth:`decode` will recover.

        Raises:
            InvalidInputError: If the length cannot come from this codec.
        """
        ...


class NoFec:
    """Identity codec: AEAD-only blobs, the crate's ``NoFec``.

    Stateless and shareable between threads.

    Example:
        >>> fec = NoFec()
        >>> fec.encode(b"data")
        b'data'
        >>> fec.decode(b"data plus padding", 4)
        b'data'
    """

    def encode(self, data: bytes) -> bytes:
        """Return ``data`` unchanged.

        Args:
            data: The protected payload ``header ‖ nonce ‖ ciphertext ‖ tag``.

        Returns:
            The same bytes.
        """
        return data

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        """Return the first ``pre_len`` bytes, bounded by what was received.

        Args:
            encoded: The received bytes.
            pre_len: The payload length reported by :meth:`validate_pre_fec`.

        Returns:
            ``encoded[:min(pre_len, len(encoded))]``.
        """
        return encoded[:pre_len]

    def validate_pre_fec(self, received: bytes) -> int:
        """Bound the received length before any decoding work.

        Args:
            received: The base64-decoded blob.

        Returns:
            The payload length to decode, which for ``NoFec`` is
            ``len(received)``.

        Raises:
            InvalidInputError: If ``received`` is longer than ``MAX_BLOB_LEN``.
        """
        if len(received) > MAX_BLOB_LEN:
            raise InvalidInputError("input exceeds maximum size")
        return len(received)


class ConcatenatedFec:
    """Reed-Solomon, then interleaver, then Viterbi: the crate's default FEC.

    Args:
        rs: The outer Reed-Solomon code.
        il: The interleaver.
        vt: The inner Viterbi code.
    """

    def __init__(self, rs: ReedSolomonCodec, il: Interleaver, vt: ViterbiCodec) -> None:
        """Compose the three stages."""
        self._rs = rs
        self._il = il
        self._vt = vt

    @classmethod
    def default(cls) -> "ConcatenatedFec":
        """Build the crate's default stack.

        RS(255, 223), a depth-5 block interleaver without the CSPRNG layer,
        and the CCSDS K=7 R=1/2 Viterbi code.

        Returns:
            The default concatenated FEC.
        """
        interleaver = Interleaver(BlockInterleaver(_DEFAULT_INTERLEAVE_DEPTH), None)
        return cls(ReedSolomonCodec(), interleaver, ViterbiCodec())

    @classmethod
    def with_csprng_from_master(cls, master: bytes, depth: int) -> "ConcatenatedFec":
        """Build a stack with the CSPRNG layer seeded from ``master``.

        Args:
            master: The 32-byte master key.
            depth: The block interleaver depth.

        Returns:
            The concatenated FEC with the CSPRNG layer.

        Raises:
            InvalidInputError: If ``master`` is not ``KEY_LEN`` bytes, checked
                first, or ``depth`` is out of range.
        """
        if len(master) != KEY_LEN:
            raise InvalidInputError(f"master key must be exactly {KEY_LEN} bytes")
        seed = expand_interleaver_seed(master)
        interleaver = Interleaver(BlockInterleaver(depth), CsprngLayer(seed))
        return cls(ReedSolomonCodec(), interleaver, ViterbiCodec())

    def encode(self, data: bytes) -> bytes:
        """Encode ``data`` through ``Viterbi(interleave(RS(data)))``.

        Args:
            data: The protected payload.

        Returns:
            The coded blob body.
        """
        return self._vt.encode(self._il.interleave(self._rs.encode(data)))

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        """Invert :meth:`encode`, correcting errors.

        Args:
            encoded: The received coded body.
            pre_len: The payload length to recover.

        Returns:
            The recovered payload.

        Raises:
            InvalidInputError: If the framing or a length is inconsistent.
            ErrorCorrectionError: If the corruption exceeds the capacity.
        """
        rs_len = _rs_stream_len(encoded)
        rs_stream = self._vt.decode(encoded)
        if len(rs_stream) != rs_len:
            raise InvalidInputError("malformed blob")
        return self._rs.decode(self._il.deinterleave(rs_stream), pre_len)

    def validate_pre_fec(self, received: bytes) -> int:
        """Check the framing before decoding.

        Args:
            received: The base64-decoded blob.

        Returns:
            The Reed-Solomon data length the body decodes to.

        Raises:
            InvalidInputError: If ``received`` is longer than ``MAX_BLOB_LEN``
                or does not frame a whole number of codewords.
        """
        return _rs_stream_len(received) // RS_BLOCK * RS_DATA


def _rs_stream_len(received: bytes) -> int:
    """Derive the Reed-Solomon stream length a concatenated body decodes to.

    Raises:
        InvalidInputError: If ``received`` is longer than ``MAX_BLOB_LEN``, is
            not a chunked Viterbi body, or does not frame a positive whole
            number of codewords.
    """
    if len(received) > MAX_BLOB_LEN:
        raise InvalidInputError("input exceeds maximum size")
    rs_len = _rs_len_from_body(len(received))
    if rs_len == 0 or rs_len % RS_BLOCK:
        raise InvalidInputError("malformed blob")
    return rs_len
