# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""The FEC strategies run on the compiled codecs, and on Python without them."""

import importlib
import sys

import pytest

from cryptovault.fec import _codecs


def test_compiled_codecs_are_the_active_backend() -> None:
    assert _codecs.NATIVE is not None
    assert _codecs.ACTIVE is _codecs.NATIVE
    assert _codecs.ACTIVE.name == "native"


def test_pure_python_codecs_take_over_without_the_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A None entry in sys.modules makes the import fail, as on a platform
    # where only the pure-Python wheel installs.
    monkeypatch.setitem(sys.modules, "cryptovault._native", None)
    try:
        reloaded = importlib.reload(_codecs)
        assert reloaded.NATIVE is None
        assert reloaded.ACTIVE is reloaded.PYTHON
    finally:
        monkeypatch.undo()
        importlib.reload(_codecs)
