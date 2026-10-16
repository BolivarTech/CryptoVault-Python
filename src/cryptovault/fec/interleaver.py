# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Interleaving stage of the concatenated FEC, the crate's ``interleaver``."""


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
        raise NotImplementedError

    def deinterleave(self, stream: bytes) -> bytes:
        """Undo :meth:`interleave`.

        Args:
            stream: An interleaved stream.

        Returns:
            The Reed-Solomon stream.
        """
        raise NotImplementedError
