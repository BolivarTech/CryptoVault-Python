# Author: Julian Bolivar
# Version: 0.3.0
# Date: 2026-10-16
"""The Reed-Solomon and Viterbi codec primitives the FEC strategies call.

The strategies never call a codec module directly: they go through
:data:`ACTIVE`, so the implementation behind the primitives can be swapped
without touching the framing logic around them.
"""

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType

from cryptovault.constants import RS_DATA, RS_PARITY
from cryptovault.fec import _viterbi
from cryptovault.fec._reedsolomon import ReedSolomon

# The pure-Python wheel, and interpreters the abi3 wheels do not cover (PyPy,
# free-threaded CPython), have no compiled extension.
_native: ModuleType | None
try:
    _native = importlib.import_module("cryptovault._native")
except ImportError:
    _native = None


@dataclass(frozen=True)
class CodecBackend:
    """One implementation of the four codec primitives.

    Attributes:
        name: Short label of the implementation.
        rs_encode: RS(255, 223) encode of a whole stream into codewords.
        rs_decode: RS(255, 223) decode of whole codewords, truncated to
            ``pre_len``; raises ``RsUncorrectableError`` or
            ``RsInvalidInputError``.
        viterbi_encode: Zero-tailed encode of one sub-block.
        viterbi_decode: Decode of one zero-tailed sub-block body.
    """

    name: str
    rs_encode: Callable[[bytes], bytes]
    rs_decode: Callable[[bytes, int], bytes]
    viterbi_encode: Callable[[bytes], bytes]
    viterbi_decode: Callable[[bytes], bytes]


_PURE_RS = ReedSolomon(RS_PARITY, RS_DATA)

PYTHON = CodecBackend(
    name="python",
    rs_encode=_PURE_RS.encode,
    rs_decode=_PURE_RS.decode,
    viterbi_encode=_viterbi.encode,
    viterbi_decode=_viterbi.decode,
)
"""The pure-Python ports of the ``reedsolomon`` and ``viterbi`` crates."""


def _wrap_native(native: ModuleType | None) -> CodecBackend | None:
    """Wrap the compiled extension, or return ``None`` when it is absent."""
    if native is None:
        return None
    return CodecBackend(
        name="native",
        rs_encode=native.rs_encode,
        rs_decode=native.rs_decode,
        viterbi_encode=native.viterbi_encode,
        viterbi_decode=native.viterbi_decode,
    )


NATIVE = _wrap_native(_native)
"""The compiled ``reedsolomon`` and ``viterbi`` crates, or ``None``."""

ACTIVE = NATIVE or PYTHON
"""The backend the FEC strategies use."""
