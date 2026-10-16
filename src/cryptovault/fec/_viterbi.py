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


# Predecessors of each state: both enter with input bit ``state >> 5``, from
# the even state first. The crate keeps the even one on a metric tie.
_PREDS: Final = [
    (
        (s & 31) << 1,
        _OUTPUT[(s & 31) << 1][s >> 5],
        ((s & 31) << 1) | 1,
        _OUTPUT[((s & 31) << 1) | 1][s >> 5],
    )
    for s in range(_STATES)
]
# Hamming distance between a received and an expected 2-bit symbol.
_DISTANCE: Final = [[(r ^ e).bit_count() for e in range(4)] for r in range(4)]
# Metric of the states the zero start cannot have reached yet.
_SENTINEL: Final = (1 << 31) - 1


def decode(body: bytes) -> bytes:
    """Hard-decision Viterbi decode of one zero-tailed block.

    ``body`` holds ``2 * n + 2`` bytes for ``n`` info bytes: ``8 * len - 4``
    coded bits, the last 4 bits being padding the decoder ignores.

    Complexity: O(len(body) * 64) time, O(len(body)) decisions kept.

    A block that is an exact codeword (the clean-channel case) is decoded by
    inverting the encoder and confirmed by re-encoding: its zero-distance path
    is then the only survivor, so the full trellis would return the same
    bytes. Any other block runs the full add-compare-select.

    Args:
        body: The coded block; even length of at least 4 (the caller checks).

    Returns:
        The ``len(body) // 2 - 1`` decoded info bytes.
    """
    stages = 4 * len(body) - 2
    symbols = [(byte >> shift) & 3 for byte in body for shift in (6, 4, 2, 0)]
    candidate = _invert(symbols, stages - _MEMORY)
    coded = encode(candidate)
    if coded[:-1] == body[:-1] and coded[-1] == body[-1] & 0xF0:
        return candidate
    return _trellis_decode(symbols, stages)


def _invert(symbols: list[int], info_bits: int) -> bytes:
    """Read the info bits off the first output of each symbol.

    That output is the input bit XOR a parity of the register state, so the
    input follows from the symbol and the state reached so far.
    """
    out = bytearray()
    state = 0
    byte = 0
    for index in range(info_bits):
        bit = (symbols[index] >> 1) ^ (_OUTPUT[state][0] >> 1)
        byte = (byte << 1) | bit
        state = _NEXT[state][bit]
        if index % 8 == 7:
            out.append(byte)
            byte = 0
    return bytes(out)


def _trellis_decode(symbols: list[int], stages: int) -> bytes:
    """Full add-compare-select over ``stages`` symbols, traceback from state 0."""
    metrics = [0] + [_SENTINEL] * (_STATES - 1)
    decisions = []
    for symbol in symbols[:stages]:
        distance = _DISTANCE[symbol]
        new = []
        chosen = 0
        for state, (from_a, out_a, from_b, out_b) in enumerate(_PREDS):
            via_a = metrics[from_a] + distance[out_a]
            via_b = metrics[from_b] + distance[out_b]
            if via_a <= via_b:
                new.append(via_a)
            else:
                new.append(via_b)
                chosen |= 1 << state
        metrics = new
        decisions.append(chosen)
    bits = []
    state = 0
    for chosen in reversed(decisions):
        bits.append(state >> 5)
        from_a, _, from_b, _ = _PREDS[state]
        state = from_b if (chosen >> state) & 1 else from_a
    bits.reverse()
    out = bytearray()
    for start in range(0, stages - _MEMORY, 8):
        byte = 0
        for bit in bits[start : start + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)
