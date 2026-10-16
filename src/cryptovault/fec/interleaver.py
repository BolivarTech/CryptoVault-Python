# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""Interleaving stage of the concatenated FEC, the crate's ``interleaver``."""

import struct
from collections.abc import Callable, Iterator

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from cryptovault.constants import KEY_LEN, NONCE_LEN, RS_BLOCK, RS_INTERLEAVE_MAX
from cryptovault.error import InvalidInputError


def _permute_windows(
    stream: bytes,
    window_len: int,
    perm_of: Callable[[int, int], list[int]],
    *,
    inverse: bool = False,
) -> bytes:
    """Apply a read-order permutation to each window of ``stream``.

    The final window may be short; it is permuted at its actual length.

    Args:
        stream: The bytes to reorder.
        window_len: Window span in bytes.
        perm_of: ``perm_of(filled, window_index)`` returns the window's read
            order: ``perm[k]`` is the source index of output byte ``k``.
        inverse: Undo the permutation instead of applying it.

    Returns:
        The reordered bytes, as long as ``stream``.
    """
    out = bytearray(len(stream))
    for index, base in enumerate(range(0, len(stream), window_len)):
        filled = min(len(stream) - base, window_len)
        for k, src in enumerate(perm_of(filled, index)):
            if inverse:
                out[base + src] = stream[base + k]
            else:
                out[base + k] = stream[base + src]
    return bytes(out)


class BlockInterleaver:
    """Deterministic block interleaver.

    Args:
        depth: Codewords per window.
    """

    def __init__(self, depth: int) -> None:
        """Validate and store the depth.

        Raises:
            InvalidInputError: If ``depth`` is outside ``1..=RS_INTERLEAVE_MAX``.
        """
        if not 1 <= depth <= RS_INTERLEAVE_MAX:
            raise InvalidInputError(
                f"interleave depth {depth} out of range 1..={RS_INTERLEAVE_MAX}"
            )
        self._depth = depth

    @property
    def depth(self) -> int:
        """Interleave depth: codewords per window."""
        return self._depth

    @property
    def window_len(self) -> int:
        """Window span in bytes: ``depth * RS_BLOCK``."""
        return self._depth * RS_BLOCK

    def interleave(self, rs_stream: bytes) -> bytes:
        """Reorder ``rs_stream`` to spread bursts across codewords.

        Args:
            rs_stream: The Reed-Solomon stream.

        Returns:
            The interleaved stream.
        """
        return _permute_windows(
            rs_stream, self.window_len, lambda filled, _: self._window_perm(filled)
        )

    def _window_perm(self, filled: int) -> list[int]:
        """Column-major read order of a window holding ``filled`` bytes.

        Row ``r`` of the ``depth x RS_BLOCK`` window is codeword ``r``;
        ``perm[k]`` is the source index of the ``k``-th output byte.
        """
        return [
            idx
            for col in range(RS_BLOCK)
            for row in range(self._depth)
            if (idx := row * RS_BLOCK + col) < filled
        ]

    def deinterleave(self, stream: bytes) -> bytes:
        """Undo :meth:`interleave`.

        Args:
            stream: An interleaved stream.

        Returns:
            The Reed-Solomon stream.
        """
        return _permute_windows(
            stream,
            self.window_len,
            lambda filled, _: self._window_perm(filled),
            inverse=True,
        )


class CsprngLayer:
    """Optional keyed shuffle applied after the block interleaver.

    Args:
        seed: The interleaver seed.
    """

    def __init__(self, seed: bytes) -> None:
        """Validate and store a copy of the seed.

        Raises:
            InvalidInputError: If ``seed`` is not exactly ``KEY_LEN`` bytes.
        """
        if len(seed) != KEY_LEN:
            raise InvalidInputError(f"interleaver seed must be exactly {KEY_LEN} bytes")
        self._seed = bytes(seed)

    def interleave(self, stream: bytes, window_len: int) -> bytes:
        """Shuffle each window of ``stream``.

        Args:
            stream: The block-interleaved stream.
            window_len: The block interleaver's window span.

        Returns:
            The shuffled stream.
        """
        return _permute_windows(stream, window_len, self._window_perm)

    def _window_perm(self, filled: int, window_index: int) -> list[int]:
        """Fisher-Yates shuffle of ``range(filled)`` keyed by seed and window.

        The keystream is ChaCha20 (IETF, counter 0) under the seed, with the
        window index as a little-endian u64 in the first 8 nonce bytes. Each
        draw is a little-endian u32, rejection-sampled to avoid modulo bias.

        Complexity: O(filled).
        """
        perm = list(range(filled))
        if filled <= 1:
            return perm
        words = self._keystream_words(window_index, filled)
        for i in range(filled - 1, 0, -1):
            bound = i + 1
            limit = (1 << 32) // bound * bound
            x = next(words)
            while x >= limit:
                x = next(words)
            j = x % bound
            perm[i], perm[j] = perm[j], perm[i]
        return perm

    def _keystream_words(self, window_index: int, batch: int) -> Iterator[int]:
        """Yield little-endian u32 words of the window's ChaCha20 keystream.

        Words are produced ``batch`` at a time; the stream never ends.
        """
        nonce = window_index.to_bytes(8, "little") + bytes(NONCE_LEN - 8)
        keystream = Cipher(
            algorithms.ChaCha20(self._seed, bytes(4) + nonce), mode=None
        ).encryptor()
        while True:
            for (word,) in struct.iter_unpack("<I", keystream.update(bytes(4 * batch))):
                yield word

    def deinterleave(self, stream: bytes, window_len: int) -> bytes:
        """Undo :meth:`interleave`.

        Args:
            stream: A shuffled stream.
            window_len: The block interleaver's window span.

        Returns:
            The block-interleaved stream.
        """
        return _permute_windows(stream, window_len, self._window_perm, inverse=True)


class Interleaver:
    """Interleaving strategy of the concatenated FEC.

    Args:
        block: The block interleaver.
        csprng: The optional CSPRNG layer.
    """

    def __init__(self, block: BlockInterleaver, csprng: CsprngLayer | None) -> None:
        """Store the stages."""
        self._block = block
        self._csprng = csprng

    def interleave(self, stream: bytes) -> bytes:
        """Interleave ``stream``.

        Args:
            stream: The Reed-Solomon stream.

        Returns:
            The interleaved stream.
        """
        blocked = self._block.interleave(stream)
        if self._csprng is None:
            return blocked
        return self._csprng.interleave(blocked, self._block.window_len)

    def deinterleave(self, stream: bytes) -> bytes:
        """Undo :meth:`interleave`.

        Args:
            stream: An interleaved stream.

        Returns:
            The Reed-Solomon stream.
        """
        if self._csprng is not None:
            stream = self._csprng.deinterleave(stream, self._block.window_len)
        return self._block.deinterleave(stream)
