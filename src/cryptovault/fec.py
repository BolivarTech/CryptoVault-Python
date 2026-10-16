# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Forward-error-correction strategies."""


class NoFec:
    """Identity codec."""

    def encode(self, data: bytes) -> bytes:
        """Encode."""
        raise NotImplementedError

    def decode(self, encoded: bytes, pre_len: int) -> bytes:
        """Decode."""
        raise NotImplementedError

    def validate_pre_fec(self, received: bytes) -> int:
        """Validate."""
        raise NotImplementedError
