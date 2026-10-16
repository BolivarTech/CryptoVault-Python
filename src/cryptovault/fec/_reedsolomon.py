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


class RsError(Exception):
    """Failure of the Reed-Solomon codec, the crate's ``RsError``."""


class RsUncorrectableError(RsError):
    """A codeword holds more errors than the code corrects."""


class RsInvalidInputError(RsError):
    """The encoded stream or the requested length is structurally invalid."""


def _poly_eval(p: list[int] | bytes | bytearray, x: int) -> int:
    """Evaluate a big-endian polynomial at ``x`` (Horner)."""
    acc = 0
    for c in p:
        acc = _mul(acc, x) ^ c
    return acc


def _syndromes(block: bytes | bytearray, parity_len: int) -> list[int]:
    """Syndromes ``S[s] = R(alpha^(FCR + s))`` for ``s < parity_len``."""
    return [_poly_eval(block, _pow(_ALPHA, _FCR + s)) for s in range(parity_len)]


def _berlekamp_massey(synd: list[int]) -> list[int]:
    """Run the inversionless Berlekamp-Massey recurrence of the crate.

    The locator may come out scaled by a non-zero constant, which changes
    neither its roots nor Forney's ratio.

    Args:
        synd: The ``2t`` syndromes.

    Returns:
        The error locator, low-endian (index = degree), trimmed.
    """
    two_t = len(synd)
    lam = [1] + [0] * two_t
    b = [1] + [0] * two_t
    length = 0
    shift = 1
    gamma = 1
    for r in range(two_t):
        delta = 0
        for i in range(min(length, r) + 1):
            delta ^= _mul(lam[i], synd[r - i])
        if delta == 0:
            shift += 1
            continue
        prev = lam
        lam = [_mul(gamma, c) for c in lam]
        for k in range(len(b) - shift):
            lam[k + shift] ^= _mul(delta, b[k])
        if 2 * length <= r:
            length = r + 1 - length
            b = prev
            gamma = delta
            shift = 1
        else:
            shift += 1
    degree = len(lam) - 1
    while degree > 0 and lam[degree] == 0:
        degree -= 1
    return lam[: degree + 1]


def _chien_search(lam_be: list[int], n: int) -> list[int]:
    """Return the positions ``j < n`` whose locator ``alpha^(n-1-j)`` is a root.

    Complexity: O(n * degree).
    """
    return [
        j
        for j in range(n)
        if _poly_eval(lam_be, _EXP[(_ORDER - (n - 1 - j) % _ORDER) % _ORDER]) == 0
    ]


def _forney(
    synd: list[int], lam_le: list[int], positions: list[int], n: int
) -> list[int]:
    """Compute the magnitudes ``X^(1-FCR) * Omega(X^-1) / Lambda'(X^-1)``.

    Omega is ``S(x) * Lambda(x) mod x^2t``; ``Lambda'`` keeps only the
    odd-degree terms, since the field has characteristic 2.

    Returns:
        One magnitude per position.

    Raises:
        RsUncorrectableError: If a denominator or a magnitude is zero.
    """
    degree = len(lam_le) - 1
    omega_le = [0] * len(synd)
    for i in range(len(synd)):
        for j in range(min(i, degree) + 1):
            omega_le[i] ^= _mul(synd[i - j], lam_le[j])
    omega_be = omega_le[::-1]
    lp_be = [lam_le[d] if d % 2 else 0 for d in range(1, degree + 1)][::-1]
    mags = []
    for j in positions:
        x = _pow(_ALPHA, (n - 1 - j) % _ORDER)
        x_inv = _EXP[_ORDER - _LOG[x]]
        num = _poly_eval(omega_be, x_inv)
        den = _poly_eval(lp_be, x_inv)
        if den == 0:
            raise RsUncorrectableError("zero/degenerate Forney magnitude")
        quotient = 0 if num == 0 else _EXP[(_LOG[num] + _ORDER - _LOG[den]) % _ORDER]
        mag = _mul(_mul(x, _pow(x_inv, _FCR)), quotient)
        if mag == 0:
            raise RsUncorrectableError("zero/degenerate Forney magnitude")
        mags.append(mag)
    return mags


def _decode_block(block: bytes, parity_len: int) -> bytes:
    """Correct one codeword and return its data bytes.

    Syndromes, Berlekamp-Massey, Chien search and Forney, then a syndrome
    check of the corrected block, in the crate's order and with its tests.

    Complexity: O(n * parity_len).

    Raises:
        RsUncorrectableError: On any inconsistency; the decoder never
            returns a block whose syndromes are not all zero.
    """
    n = len(block)
    data_len = n - parity_len
    synd = _syndromes(block, parity_len)
    if not any(synd):
        return block[:data_len]
    lam_le = _berlekamp_massey(synd)
    degree = len(lam_le) - 1
    if degree == 0 or degree > parity_len // 2:
        raise RsUncorrectableError("lambda degree > t")
    positions = _chien_search(lam_le[::-1], n)
    if len(positions) != degree:
        raise RsUncorrectableError("Chien root count != lambda degree")
    corrected = bytearray(block)
    for j, mag in zip(positions, _forney(synd, lam_le, positions, n), strict=True):
        corrected[j] ^= mag
    if any(_syndromes(corrected, parity_len)):
        raise RsUncorrectableError("post-correction syndromes nonzero")
    return bytes(corrected[:data_len])


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

    def decode(self, encoded: bytes, original_len: int) -> bytes:
        """Correct every codeword, then truncate to ``original_len``.

        Complexity: O(len(encoded) * parity_len) per clean codeword, plus
        O(n * t) for each codeword with errors.

        Args:
            encoded: Whole codewords.
            original_len: The data length to recover; it must need exactly
                as many codewords as ``encoded`` holds.

        Returns:
            The first ``original_len`` data bytes.

        Raises:
            RsInvalidInputError: If the lengths are inconsistent.
            RsUncorrectableError: If a codeword cannot be corrected.
        """
        n = self._data_len + self._parity_len
        if not encoded:
            if original_len == 0:
                return b""
            raise RsInvalidInputError("empty encoded but original_len > 0")
        if len(encoded) % n:
            raise RsInvalidInputError("encoded length not a multiple of n")
        blocks = len(encoded) // n
        needed = -(-original_len // self._data_len)
        if needed != blocks or original_len > blocks * self._data_len:
            raise RsInvalidInputError("original_len inconsistent with blocks")
        out = bytearray()
        for start in range(0, len(encoded), n):
            out += _decode_block(encoded[start : start + n], self._parity_len)
        return bytes(out[:original_len])
