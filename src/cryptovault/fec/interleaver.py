# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Interleaving stage of the concatenated FEC, the crate's ``interleaver``."""

from cryptovault.constants import RS_BLOCK


class BlockInterleaver:
    """Deterministic block interleaver.

    Args:
        depth: Codewords per window.
    """

    def __init__(self, depth: int) -> None:
        """Store the depth."""
        self._depth = depth

    def interleave(self, rs_stream: bytes) -> bytes:
        """Reorder ``rs_stream`` to spread bursts across codewords.

        Args:
            rs_stream: The Reed-Solomon stream.

        Returns:
            The interleaved stream.
        """
        out = bytearray(len(rs_stream))
        window = self._depth * RS_BLOCK
        for base in range(0, len(rs_stream), window):
            filled = min(len(rs_stream) - base, window)
            for k, src in enumerate(self._window_perm(filled)):
                out[base + k] = rs_stream[base + src]
        return bytes(out)

    def _window_perm(self, filled: int) -> list[int]:
        """Column-major read order of a window holding ``filled`` bytes.

        Row ``r`` of the ``depth x RS_BLOCK`` window is codeword ``r``;
        ``perm[k]`` is the source index of the ``k``-th output byte.
        """
        return [
            idx
            for col in range(RS_BLOCK)
            for row in range(self._depth)
            if (idx := row * RS_BLOCK + col) < filled
        ]

    def deinterleave(self, stream: bytes) -> bytes:
        """Undo :meth:`interleave`.

        Args:
            stream: An interleaved stream.

        Returns:
            The Reed-Solomon stream.
        """
        out = bytearray(len(stream))
        window = self._depth * RS_BLOCK
        for base in range(0, len(stream), window):
            filled = min(len(stream) - base, window)
            for k, dst in enumerate(self._window_perm(filled)):
                out[base + dst] = stream[base + k]
        return bytes(out)
