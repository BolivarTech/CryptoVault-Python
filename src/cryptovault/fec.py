# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Forward-error-correction strategies.

The FEC layer only adds channel resilience; confidentiality and integrity come
from the AEAD, applied first. A blob decodes only with the strategy that
encoded it. This stage ships :class:`NoFec`, the identity codec; the crate's
Reed-Solomon, interleaver and Viterbi codecs come in a later stage.
"""

from cryptovault.constants import MAX_BLOB_LEN
from cryptovault.error import InvalidInputError


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
