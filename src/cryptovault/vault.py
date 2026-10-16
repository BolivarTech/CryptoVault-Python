# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""The vault: composes key derivation, AEAD and FEC strategies."""

import base64
import binascii
import struct

from cryptovault._blob import decode_blob
from cryptovault.cipher import Aes256GcmSivCipher, sample_nonce
from cryptovault.constants import (
    BLOB_VERSION,
    KEY_LEN,
    MAX_B64_LEN,
    MAX_BLOB_LEN,
    MAX_PLAINTEXT_LEN,
    NONCE_LEN,
    SALT_LEN,
)
from cryptovault.error import EncodingError, InvalidInputError
from cryptovault.fec import NoFec
from cryptovault.kdf import Argon2Kdf, expand_aead_key

_AAD_PURPOSE_DATA = 0x01


def _decode_base64(text: str) -> bytes:
    """Decode strict, canonical, padded standard base64, as the crate does.

    ``base64.b64decode`` accepts set trailing bits and some extra padding even
    with ``validate=True``; re-encoding the result and comparing closes both.

    Args:
        text: The blob as received.

    Returns:
        The decoded bytes.

    Raises:
        EncodingError: ``"invalid encoding"`` for any character outside the
            standard alphabet (whitespace included), missing or extra padding,
            or trailing bits that are not zero.
    """
    try:
        raw = text.encode("ascii")
        decoded = base64.b64decode(raw, validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise EncodingError("invalid encoding") from exc
    if base64.b64encode(decoded) != raw:
        raise EncodingError("invalid encoding")
    return decoded


class CryptoVault:
    """The crate's ``CryptoVault``."""

    def __init__(self, kdf: Argon2Kdf, cipher: Aes256GcmSivCipher, fec: NoFec) -> None:
        """Compose the three strategies."""
        self._kdf = kdf
        self._cipher = cipher
        self._fec = fec
        self._max_blob_len = MAX_BLOB_LEN

    def with_max_blob_len(self, cap: int) -> "CryptoVault":
        """Return a vault with a lower decoded-blob cap."""
        capped = CryptoVault(self._kdf, self._cipher, self._fec)
        capped._max_blob_len = min(cap, MAX_BLOB_LEN)
        return capped

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a master key from a password."""
        if not password:
            raise InvalidInputError("password must not be empty")
        if len(salt) != SALT_LEN:
            raise InvalidInputError(f"salt must be exactly {SALT_LEN} bytes")
        return self._kdf.derive_master(password.encode("utf-8"), salt)

    def encrypt_with_key(self, key: bytes, plaintext: str) -> str:
        """Encrypt text into a data blob."""
        if len(key) != KEY_LEN:
            raise InvalidInputError(f"master key must be exactly {KEY_LEN} bytes")
        try:
            data = plaintext.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EncodingError("plaintext is not valid UTF-8") from exc
        if len(data) > MAX_PLAINTEXT_LEN:
            raise InvalidInputError("plaintext exceeds maximum size")
        header = bytes([BLOB_VERSION]) + struct.pack("<I", len(data))
        aad = bytes([_AAD_PURPOSE_DATA]) + header
        nonce = sample_nonce()
        sealed = self._cipher.encrypt(expand_aead_key(key), nonce, aad, data)
        blob = self._fec.encode(header + nonce + sealed)
        return base64.b64encode(blob).decode("ascii")

    def decrypt_with_key(self, key: bytes, blob: str) -> str:
        """Decrypt a data blob."""
        if len(key) != KEY_LEN:
            raise InvalidInputError(f"master key must be exactly {KEY_LEN} bytes")
        # Rust measures the str in UTF-8 bytes; for ASCII that is len(blob).
        if blob.isascii():
            blob_len = len(blob)
        else:
            blob_len = len(blob.encode("utf-8", "surrogatepass"))
        if blob_len > MAX_B64_LEN:
            raise InvalidInputError("input exceeds maximum size")
        received = _decode_base64(blob)
        if len(received) > self._max_blob_len:
            raise InvalidInputError("input exceeds maximum size")
        version, plaintext_len, body = decode_blob(self._fec, received)
        header = bytes([version]) + struct.pack("<I", plaintext_len)
        aad = bytes([_AAD_PURPOSE_DATA]) + header
        nonce, sealed = body[:NONCE_LEN], body[NONCE_LEN:]
        plaintext = self._cipher.decrypt(expand_aead_key(key), nonce, aad, sealed)
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            # Rust's Utf8Error stops at the same byte and measures the bad
            # sequence the same way; only the wording differs.
            if exc.reason == "unexpected end of data":
                detail = f"incomplete utf-8 byte sequence from index {exc.start}"
            else:
                size = exc.end - exc.start
                detail = (
                    f"invalid utf-8 sequence of {size} bytes from index {exc.start}"
                )
            raise EncodingError(
                f"decrypted plaintext is not valid UTF-8: {detail}"
            ) from exc
