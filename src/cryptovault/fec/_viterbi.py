# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""CCSDS K=7 R=1/2 convolutional code, a port of the ``viterbi`` 0.2.0 crate.

Generators ``0o171`` and ``0o133``, the second output inverted, first
generator in the high bit of each 2-bit symbol. The shift register holds the
newest input bit in bit 6 of ``(input << 6) | state``; bits are packed MSB
first, and every block ends with a 6-stage zero tail back to state 0.
"""

from typing import Final

_MEMORY: Final = 6
_STATES: Final = 1 << _MEMORY
_GENERATORS: Final = ((0o171, False), (0o133, True))


def _next_state(state: int, bit: int) -> int:
    """Shift ``bit`` into the register."""
    return (((bit << _MEMORY) | state) >> 1) & (_STATES - 1)


def _output_symbol(state: int, bit: int) -> int:
    """2-bit output symbol for ``bit`` entering from ``state``."""
    register = (bit << _MEMORY) | state
    symbol = 0
    for generator, inverted in _GENERATORS:
        symbol = (symbol << 1) | ((register & generator).bit_count() & 1) ^ inverted
    return symbol


_OUTPUT: Final = [[_output_symbol(s, b) for b in (0, 1)] for s in range(_STATES)]
_NEXT: Final = [[_next_state(s, b) for b in (0, 1)] for s in range(_STATES)]


def encode(data: bytes) -> bytes:
    """Encode every bit of ``data`` and flush the register with a zero tail.

    Each info byte yields exactly two coded bytes; the 6-stage tail yields 12
    bits, padded with 4 zero bits to a whole byte.

    Complexity: O(len(data)).

    Args:
        data: The info bytes.

    Returns:
        ``2 * len(data) + 2`` coded bytes.
    """
    out = bytearray()
    state = 0
    for byte in data:
        word = 0
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            word = (word << 2) | _OUTPUT[state][bit]
            state = _NEXT[state][bit]
        out += word.to_bytes(2, "big")
    tail = 0
    for _ in range(_MEMORY):
        tail = (tail << 2) | _OUTPUT[state][0]
        state = _NEXT[state][0]
    out += (tail << 4).to_bytes(2, "big")
    return bytes(out)
