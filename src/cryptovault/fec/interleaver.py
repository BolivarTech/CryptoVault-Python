# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Interleaving stage of the concatenated FEC, the crate's ``interleaver``."""

from cryptovault.constants import RS_BLOCK, RS_INTERLEAVE_MAX
from cryptovault.error import InvalidInputError


class BlockInterleaver:
    """Deterministic block interleaver.

    Args:
        depth: Codewords per window.
    """

    def __init__(self, depth: int) -> None:
        """Validate and store the depth.

        Raises:
            InvalidInputError: If ``depth`` is outside ``1..=RS_INTERLEAVE_MAX``.
        """
        if not 1 <= depth <= RS_INTERLEAVE_MAX:
            raise InvalidInputError(
                f"interleave depth {depth} out of range 1..={RS_INTERLEAVE_MAX}"
            )
        self._depth = depth

    @property
    def depth(self) -> int:
        """Interleave depth: codewords per window."""
        return self._depth

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


class CsprngLayer:
    """Optional keyed shuffle applied after the block interleaver.

    Args:
        seed: The interleaver seed.
    """

    def __init__(self, seed: bytes) -> None:
        """Store the seed."""
        self._seed = seed

    def interleave(self, stream: bytes, window_len: int) -> bytes:
        """Shuffle each window of ``stream``.

        Args:
            stream: The block-interleaved stream.
            window_len: The block interleaver's window span.

        Returns:
            The shuffled stream.
        """
        raise NotImplementedError

    def deinterleave(self, stream: bytes, window_len: int) -> bytes:
        """Undo :meth:`interleave`.

        Args:
            stream: A shuffled stream.
            window_len: The block interleaver's window span.

        Returns:
            The block-interleaved stream.
        """
        raise NotImplementedError
