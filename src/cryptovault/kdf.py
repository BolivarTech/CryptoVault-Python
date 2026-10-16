# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Key-derivation strategy: Argon2id master key, HKDF-SHA256 sub-keys."""

from typing import Final, Protocol, runtime_checkable

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptovault.constants import ARGON2_M_KIB, ARGON2_P, ARGON2_T, KEY_LEN
from cryptovault.error import KeyDerivationError

_HKDF_INFO_AEAD: Final = b"cryptovault:v1:aead"
"""HKDF ``info`` label of the AEAD sub-key."""


@runtime_checkable
class KeyDerivation(Protocol):
    """Master-key derivation strategy, the crate's ``KeyDerivation`` trait."""

    def derive_master(self, password: bytes, salt: bytes) -> bytes:
        """Derive the 32-byte master key from a password and a salt.

        Args:
            password: The password, as bytes.
            salt: The per-context salt.

        Returns:
            The 32-byte master key.

        Raises:
            KeyDerivationError: If the derivation fails.
        """
        ...


class Argon2Kdf:
    """Argon2id v1.3 with the crate's OWASP-2025 profile.

    Memory 64 MiB (``ARGON2_M_KIB``), 3 passes, 4 lanes, 32-byte output.
    Stateless: an instance holds no key and may be shared between threads.
    """

    def derive_master(self, password: bytes, salt: bytes) -> bytes:
        """Derive the 32-byte master key from a password and a salt.

        Costs 64 MiB of memory and noticeable CPU per call: derive once per
        session and keep the result.

        Args:
            password: The password, as bytes.
            salt: The per-context salt.

        Returns:
            The 32-byte master key.

        Raises:
            KeyDerivationError: If the backend rejects the parameters or does
                not support Argon2id (OpenSSL older than 3.2).
        """
        try:
            kdf = Argon2id(
                salt=salt,
                length=KEY_LEN,
                iterations=ARGON2_T,
                lanes=ARGON2_P,
                memory_cost=ARGON2_M_KIB,
            )
            return kdf.derive(password)
        except (UnsupportedAlgorithm, ValueError) as exc:
            raise KeyDerivationError(f"Argon2id derivation failed: {exc}") from exc


def expand_aead_key(master: bytes) -> bytes:
    """Expand the AES-256-GCM-SIV key from a master key.

    ``HKDF-SHA256(salt = none, ikm = master, info = "cryptovault:v1:aead")``.
    The raw master key is never used as a cipher key.

    Args:
        master: The 32-byte master key.

    Returns:
        The 32-byte AEAD key.
    """
    return _hkdf_expand(master, _HKDF_INFO_AEAD)


def _hkdf_expand(master: bytes, info: bytes) -> bytes:
    """Run HKDF-SHA256 (RFC 5869) with no salt and a 32-byte output.

    Args:
        master: The input keying material.
        info: The context label that separates sub-keys.

    Returns:
        The 32-byte output keying material.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info)
    return hkdf.derive(master)
