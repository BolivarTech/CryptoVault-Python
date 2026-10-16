# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""Key-derivation strategy: Argon2id master key, HKDF-SHA256 sub-keys."""

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from cryptovault.constants import ARGON2_M_KIB, ARGON2_P, ARGON2_T, KEY_LEN


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
        """
        kdf = Argon2id(
            salt=salt,
            length=KEY_LEN,
            iterations=ARGON2_T,
            lanes=ARGON2_P,
            memory_cost=ARGON2_M_KIB,
        )
        return kdf.derive(password)
