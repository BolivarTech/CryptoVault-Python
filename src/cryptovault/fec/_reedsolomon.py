# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Reed-Solomon over GF(2^8), a port of the ``reedsolomon`` 0.2.0 crate.

The crate ``cryptovault`` delegates its outer code to that crate, so this
module follows it step by step: the field (polynomial ``0x187``, generator
``alpha = 2``), the code generator with first consecutive root ``alpha^112``,
and the systematic block layout (data in the high positions, parity last,
final block zero-padded).
"""

from typing import Final

_FIELD_POLY: Final = 0x187
_ALPHA: Final = 2
_FCR: Final = 112
_ORDER: Final = 255


def _build_tables() -> tuple[list[int], list[int]]:
    """Build the antilog table (doubled, to skip a modulo) and the log table.

    Returns:
        ``(exp, log)`` with ``exp[i] = alpha^i`` for ``i < 510``.
    """
    exp = [0] * (2 * 256)
    log = [0] * 256
    x = 1
    for i in range(_ORDER):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _FIELD_POLY
    for j in range(_ORDER, 2 * 256):
        exp[j] = exp[j - _ORDER]
    return exp, log


_EXP, _LOG = _build_tables()


def _mul(a: int, b: int) -> int:
    """Multiply two field elements."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _pow(base: int, exp: int) -> int:
    """Raise a field element to a non-negative integer power."""
    if exp == 0:
        return 1
    if base == 0:
        return 0
    return _EXP[(_LOG[base] * (exp % _ORDER)) % _ORDER]


def _poly_mul(a: list[int], b: list[int]) -> list[int]:
    """Multiply two big-endian polynomials."""
    out = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        for j, cb in enumerate(b):
            out[i + j] ^= _mul(ca, cb)
    return out


def _poly_remainder(dividend: list[int], divisor: list[int]) -> list[int]:
    """Remainder of big-endian polynomial division by a monic ``divisor``.

    Returns:
        Exactly ``len(divisor) - 1`` coefficients.
    """
    work = list(dividend)
    dl = len(divisor)
    for i in range(max(len(work) - (dl - 1), 0)):
        coef = work[i]
        if coef:
            for j in range(1, dl):
                work[i + j] ^= _mul(divisor[j], coef)
    return work[len(work) - (dl - 1) :]


class ReedSolomon:
    """A Reed-Solomon code with ``data_len`` data and ``parity_len`` parity bytes.

    Args:
        parity_len: Parity bytes per codeword.
        data_len: Data bytes per codeword.
    """

    __slots__ = ("_data_len", "_generator", "_parity_len")

    def __init__(self, parity_len: int, data_len: int) -> None:
        self._parity_len = parity_len
        self._data_len = data_len
        generator = [1]
        for i in range(parity_len):
            generator = _poly_mul(generator, [1, _pow(_ALPHA, _FCR + i)])
        self._generator = generator

    def encode(self, data: bytes) -> bytes:
        """Encode ``data`` block by block, zero-padding the final block.

        Complexity: O(len(data) * parity_len).

        Args:
            data: The bytes to protect.

        Returns:
            ``ceil(len(data) / data_len)`` codewords, empty for empty input.
        """
        out = bytearray()
        for start in range(0, len(data), self._data_len):
            chunk = data[start : start + self._data_len]
            block = [*chunk, *([0] * (self._data_len - len(chunk) + self._parity_len))]
            block[self._data_len :] = _poly_remainder(block, self._generator)
            out += bytes(block)
        return bytes(out)
