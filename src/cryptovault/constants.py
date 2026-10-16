# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Wire-format constants, with the values of the ``cryptovault`` crate 0.3.0.

The blob size limits are derived exactly as the crate derives them. The crate
sizes them for its concatenated FEC stack, and they apply unchanged to
``NoFec`` blobs, so a blob is rejected on the same lengths in both languages.
"""

from typing import Final

KEY_LEN: Final = 32
"""AES-256 key length and master-key length, in bytes."""

SALT_LEN: Final = 16
"""Argon2id salt length, in bytes."""

NONCE_LEN: Final = 12
"""AES-256-GCM-SIV nonce length, in bytes."""

TAG_LEN: Final = 16
"""AEAD authentication tag length, in bytes."""

HEADER_LEN: Final = 5
"""Blob header length: ``version (1)`` + ``plaintext_len (u32 LE, 4)``."""

BLOB_VERSION: Final = 1
"""The only blob format version accepted."""

MAX_PLAINTEXT_LEN: Final = 10 * 1024 * 1024
"""Largest plaintext accepted in one blob (10 MiB)."""

RECOMMENDED_MAX_PAYLOAD: Final = 128 * 1024
"""Recommended largest plaintext per blob (128 KiB); frame larger data."""

ARGON2_M_KIB: Final = 65536
"""Argon2id memory cost, KiB (OWASP 2025: 64 MiB)."""

ARGON2_T: Final = 3
"""Argon2id time cost (iterations)."""

ARGON2_P: Final = 4
"""Argon2id parallelism (lanes)."""

RS_DATA: Final = 223
"""Reed-Solomon data bytes per codeword."""

RS_PARITY: Final = 32
"""Reed-Solomon parity bytes per codeword."""

RS_BLOCK: Final = RS_DATA + RS_PARITY
"""Reed-Solomon codeword length, in bytes (255)."""

RS_INTERLEAVE_MAX: Final = 16
"""Largest interleave depth: codewords per interleaver window."""

VITERBI_CHUNK: Final = 490 * RS_BLOCK
"""Reed-Solomon stream bytes per Viterbi sub-block (124 950)."""

TERMINATION_OVERHEAD: Final = 2
"""Bytes the Viterbi zero tail adds to each sub-block (``2L + 2``)."""


def _max_blob_len() -> int:
    """Derive the crate's ``MAX_BLOB_LEN``.

    The largest protected payload is expanded by Reed-Solomon (``255/223``,
    whole codewords), doubled by the Viterbi inner code, and given a two-byte
    zero tail per Viterbi sub-block.

    Returns:
        The largest decoded blob length accepted, in bytes.
    """
    protected_max = MAX_PLAINTEXT_LEN + HEADER_LEN + NONCE_LEN + TAG_LEN
    rs_max = -(-protected_max // RS_DATA) * RS_BLOCK
    viterbi_chunks = -(-rs_max // VITERBI_CHUNK)
    return rs_max * 2 + TERMINATION_OVERHEAD * viterbi_chunks


MAX_BLOB_LEN: Final = _max_blob_len()
"""Largest decoded blob accepted, in bytes (23 981 412)."""

MAX_B64_LEN: Final = MAX_BLOB_LEN * 4 // 3 + 4
"""Largest base64 input accepted, checked before decoding (31 975 220)."""
