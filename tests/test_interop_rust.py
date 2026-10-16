# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Python to Rust: the real crate opens every blob this package produces (CV-16).

Needs the Rust toolchain, so it is deselected by default. Run it with::

    uv run pytest -m interop
"""

import json
import pathlib
import shutil
import subprocess

import pytest

from cryptovault import Aes256GcmSivCipher, Argon2Kdf, CryptoVault, NoFec

pytestmark = pytest.mark.interop

MANIFEST = pathlib.Path(__file__).parents[1] / "interop" / "rust" / "Cargo.toml"
PLAINTEXTS = ["", "a", "sk-secret", "ñandú \U0001f510 中文", "x" * 131072]
ENVELOPES = [
    (bytes(range(16)), bytes(range(64, 96))),
    (b"", bytes(32)),
    (bytes(16), b""),
    (b"\xaa" * 40, b"\x55" * 64),
]


def test_the_rust_crate_opens_every_blob_python_produces(
    tmp_path: pathlib.Path,
) -> None:
    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.fail(
            "cargo is required for -m interop: install Rust from https://rustup.rs"
        )
    vault = CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())
    key, kek = bytes(range(32)), bytes(range(0x60, 0x80))
    document = {
        "data": [
            {"key": key.hex(), "plaintext": p, "blob": vault.encrypt_with_key(key, p)}
            for p in PLAINTEXTS
        ],
        "envelope": [
            {
                "kek": kek.hex(),
                "salt": salt.hex(),
                "key_material": material.hex(),
                "blob": vault.wrap_key(kek, salt, material),
            }
            for salt, material in ENVELOPES
        ],
    }
    path = tmp_path / "python_blobs.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = subprocess.run(
        [
            cargo,
            "run",
            "-q",
            "--release",
            "--manifest-path",
            str(MANIFEST),
            "--",
            "verify",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verified 9 passed, 0 failed" in result.stdout
