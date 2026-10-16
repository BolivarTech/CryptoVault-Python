# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Forward-error-correction strategies.

The FEC layer only adds channel resilience; confidentiality and integrity come
from the AEAD, applied first. A blob decodes only with the strategy that
encoded it. This stage ships :class:`NoFec`, the identity codec; the crate's
Reed-Solomon, interleaver and Viterbi codecs come in a later stage.
"""

from typing import Protocol

from cryptovault.constants import MAX_BLOB_LEN
from cryptovault.error import InvalidInputError
from cryptovault.fec.interleaver import BlockInterleaver, CsprngLayer, Interleaver
from cryptovault.fec.rs import ReedSolomonCodec
from cryptovault.fec.viterbi import ViterbiCodec, ViterbiOnlyFec

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

    def encode(self, data: bytes) -> bytes:
        """Encode ``data`` through ``Viterbi(interleave(RS(data)))``.

        Args:
            data: The protected payload.

        Returns:
            The coded blob body.
        """
        raise NotImplementedError

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        """Invert :meth:`encode`, correcting errors.

        Args:
            encoded: The received coded body.
            pre_len: The payload length to recover.

        Returns:
            The recovered payload.
        """
        raise NotImplementedError

    def validate_pre_fec(self, received: bytes) -> int:
        """Check the framing before decoding.

        Args:
            received: The base64-decoded blob.

        Returns:
            The Reed-Solomon data length the body decodes to.
        """
        raise NotImplementedError
