# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Reed-Solomon RS(255, 223) outer code, the crate's ``ReedSolomonCodec``."""


class ReedSolomonCodec:
    """Reed-Solomon RS(255, 223) outer code."""

    def encode(self, data: bytes) -> bytes:
        """Encode ``data`` into whole codewords.

        Args:
            data: The bytes to protect.

        Returns:
            The codewords.
        """
        raise NotImplementedError
