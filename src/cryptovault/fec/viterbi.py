# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Viterbi inner code, the crate's ``ViterbiCodec`` and ``ViterbiOnlyFec``."""

from cryptovault.constants import VITERBI_CHUNK
from cryptovault.fec import _viterbi


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
