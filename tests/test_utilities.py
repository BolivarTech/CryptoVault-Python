# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Salt and DEK generation and constant-time comparison (CV-12, CV-15)."""

import os
from collections.abc import Callable

import pytest

from cryptovault.error import KeyDerivationError
from cryptovault.vault import constant_time_eq, generate_dek, generate_salt


@pytest.mark.parametrize(
    ("generate", "size"), [(generate_salt, 16), (generate_dek, 32)], ids=["salt", "dek"]
)
def test_generators_return_fresh_random_bytes_or_fail_closed(
    monkeypatch: pytest.MonkeyPatch, generate: Callable[[], bytes], size: int
) -> None:
    first, second = generate(), generate()
    assert len(first) == len(second) == size
    assert first != second

    def no_entropy(count: int) -> bytes:
        raise OSError("entropy source unavailable")

    monkeypatch.setattr(os, "urandom", no_entropy)
    with pytest.raises(KeyDerivationError) as caught:
        generate()
    assert caught.value.message.startswith("OsRng entropy failure: ")
    assert isinstance(caught.value.__cause__, OSError)


@pytest.mark.parametrize(
    ("a", "b", "equal"),
    [
        (b"", b"", True),
        (b"secret", b"secret", True),
        (b"secret", b"secreT", False),
        (b"secret", b"secret!", False),
        (b"", b"\x00", False),
    ],
)
def test_constant_time_eq_compares_whole_byte_strings(
    a: bytes, b: bytes, equal: bool
) -> None:
    assert constant_time_eq(a, b) is equal
