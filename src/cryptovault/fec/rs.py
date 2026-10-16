# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Reed-Solomon RS(255, 223) outer code, the crate's ``ReedSolomonCodec``."""

from cryptovault.constants import RS_DATA, RS_PARITY
from cryptovault.fec._reedsolomon import ReedSolomon

_RS = ReedSolomon(RS_PARITY, RS_DATA)


class ReedSolomonCodec:
    """Reed-Solomon RS(255, 223) outer code."""

    def encode(self, data: bytes) -> bytes:
        """Encode ``data`` into whole codewords.

        Args:
            data: The bytes to protect.

        Returns:
            The codewords.
        """
        return _RS.encode(data)
