# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Type stub of the compiled codec extension (``native/src/lib.rs``)."""

def rs_encode(data: bytes) -> bytes:
    """RS(255, 223) encode into codewords, the last one zero-padded."""

def rs_decode(encoded: bytes, pre_len: int) -> bytes:
    """Correct whole RS(255, 223) codewords and truncate to ``pre_len``."""

def viterbi_encode(chunk: bytes) -> bytes:
    """Encode one zero-tailed CCSDS K=7 R=1/2 sub-block."""

def viterbi_decode(body: bytes) -> bytes:
    """Hard-decision decode of one zero-tailed sub-block body."""
