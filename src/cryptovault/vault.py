# Author: Julian Bolivar
# Version: 0.2.0
# Date: 2026-10-16
"""The vault, which composes key derivation, AEAD and FEC strategies.

Also holds the random-value helpers and the constant-time comparison the
crate exposes next to its vault.
"""

import base64
import binascii
import hmac
import os
import struct
from typing import Final

from cryptovault._blob import decode_blob
from cryptovault.cipher import Aes256GcmSivCipher, AuthenticatedCipher, sample_nonce
from cryptovault.constants import (
    BLOB_VERSION,
    KEY_LEN,
    MAX_B64_LEN,
    MAX_BLOB_LEN,
    MAX_PLAINTEXT_LEN,
    NONCE_LEN,
    SALT_LEN,
)
from cryptovault.error import EncodingError, InvalidInputError, KeyDerivationError
from cryptovault.fec import ConcatenatedFec, ErrorCorrection
from cryptovault.kdf import Argon2Kdf, KeyDerivation, expand_aead_key

_AAD_PURPOSE_DATA: Final = 0x01
"""First AAD byte of data blobs; keeps them from opening as envelopes."""

_AAD_PURPOSE_ENVELOPE: Final = 0x02
"""First AAD byte of wrapped keys; keeps them from opening as data."""

_KEY_LEN_MESSAGE: Final = f"master key must be exactly {KEY_LEN} bytes"
_TOO_LARGE_MESSAGE: Final = "input exceeds maximum size"
_LEN_FIELD: Final = struct.Struct("<I")


def _random_bytes(count: int) -> bytes:
    """Draw bytes from the operating-system CSPRNG, failing closed.

    Args:
        count: How many bytes to draw.

    Returns:
        ``count`` random bytes.

    Raises:
        KeyDerivationError: If the operating system cannot supply entropy.
            Weak bytes are never returned instead.
    """
    try:
        return os.urandom(count)
    except OSError as exc:
        raise KeyDerivationError(f"OsRng entropy failure: {exc}") from exc


def generate_salt() -> bytes:
    """Generate a fresh 16-byte Argon2id salt from the OS CSPRNG.

    Use one salt per context and never reuse it: the same password and salt
    give the same master key. The salt is not secret, but it is not stored in
    any blob either; the caller keeps it.

    Returns:
        ``SALT_LEN`` (16) random bytes.

    Raises:
        KeyDerivationError: If the operating system cannot supply entropy.
    """
    return _random_bytes(SALT_LEN)


def generate_dek() -> bytes:
    """Generate a fresh 32-byte data-encryption key from the OS CSPRNG.

    Returns:
        ``KEY_LEN`` (32) random bytes, usable as a master key or wrapped with
        :meth:`CryptoVault.wrap_key`.

    Raises:
        KeyDerivationError: If the operating system cannot supply entropy.
    """
    return _random_bytes(KEY_LEN)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in time that does not depend on their content.

    Args:
        a: First value.
        b: Second value.

    Returns:
        ``True`` only if both have the same length and the same bytes.

    Example:
        >>> constant_time_eq(b"tag", b"tag"), constant_time_eq(b"tag", b"tab")
        (True, False)
    """
    return hmac.compare_digest(a, b)


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


def _utf8_len(text: str) -> int:
    """Return the length of ``text`` in UTF-8 bytes, the unit Rust measures.

    O(1) for ASCII text, which every valid blob is; O(n) otherwise.

    Args:
        text: Any string, lone surrogates included.

    Returns:
        The number of bytes ``text`` takes in UTF-8.
    """
    if text.isascii():
        return len(text)
    return len(text.encode("utf-8", "surrogatepass"))


def _utf8_error_detail(exc: UnicodeDecodeError) -> str:
    """Render a UTF-8 decode error the way Rust's ``Utf8Error`` displays it.

    Both decoders stop at the same byte and measure the invalid sequence the
    same way (maximal subparts), so only the wording has to be translated.

    Args:
        exc: The error raised by ``bytes.decode("utf-8")``.

    Returns:
        ``"invalid utf-8 sequence of N bytes from index I"``, or
        ``"incomplete utf-8 byte sequence from index I"`` when the input ends
        in the middle of a sequence.
    """
    if exc.reason == "unexpected end of data":
        return f"incomplete utf-8 byte sequence from index {exc.start}"
    size = exc.end - exc.start
    return f"invalid utf-8 sequence of {size} bytes from index {exc.start}"


def _build_header(plaintext_len: int) -> bytes:
    """Return ``version ‖ plaintext_len (u32 LE)``, the 5-byte blob header."""
    return bytes([BLOB_VERSION]) + _LEN_FIELD.pack(plaintext_len)


class CryptoVault:
    """Authenticated encryption into blobs the ``cryptovault`` crate can open.

    The vault composes three strategies, as ``CryptoVault::new`` does: key
    derivation, an AEAD cipher and a forward-error-correction codec. A blob
    opens only with the strategy that produced it. :meth:`default` builds the
    crate's default vault, with the concatenated FEC; the constructor has no
    defaults, so every strategy is a visible choice.

    The instance keeps no secrets and no state between calls: the caller holds
    the 32-byte key and passes it to each call. One instance may be shared
    between threads.

    Args:
        kdf: Derives master keys from passwords (``Argon2Kdf``).
        cipher: Seals and opens the payload (``Aes256GcmSivCipher``).
        fec: Adds and removes channel redundancy (``ConcatenatedFec``,
            ``ViterbiOnlyFec``, ``ReedSolomonCodec`` or ``NoFec``).

    Example:
        >>> from cryptovault import Aes256GcmSivCipher, Argon2Kdf, NoFec
        >>> vault = CryptoVault(Argon2Kdf(), Aes256GcmSivCipher(), NoFec())
        >>> key = generate_dek()
        >>> vault.decrypt_with_key(key, vault.encrypt_with_key(key, "hi"))
        'hi'
    """

    __slots__ = ("_cipher", "_fec", "_kdf", "_max_blob_len")

    def __init__(
        self, kdf: KeyDerivation, cipher: AuthenticatedCipher, fec: ErrorCorrection
    ) -> None:
        """Compose the three strategies, with the decoded-blob cap at its maximum."""
        self._kdf = kdf
        self._cipher = cipher
        self._fec = fec
        self._max_blob_len = MAX_BLOB_LEN

    @classmethod
    def default(cls) -> "CryptoVault":
        """Build the crate's default vault, ``CryptoVault::default()``.

        Argon2id, AES-256-GCM-SIV and the default concatenated FEC
        (:meth:`ConcatenatedFec.default`).

        Returns:
            The default vault.
        """
        return cls(Argon2Kdf(), Aes256GcmSivCipher(), ConcatenatedFec.default())

    def with_max_blob_len(self, cap: int) -> "CryptoVault":
        """Return a new vault that rejects decoded blobs longer than ``cap``.

        Lowering the cap bounds the work an untrusted blob can cause before
        authentication. The original vault is left unchanged.

        Args:
            cap: The largest decoded blob to accept, in bytes. Values above
                ``MAX_BLOB_LEN`` are clamped to it.

        Returns:
            A vault with the same strategies and the new cap.
        """
        capped = CryptoVault(self._kdf, self._cipher, self._fec)
        capped._max_blob_len = min(cap, MAX_BLOB_LEN)
        return capped

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 32-byte master key from a password and a salt.

        Runs Argon2id with 64 MiB of memory: call it once per session and keep
        the key, and rate-limit it when callers are untrusted.

        Args:
            password: A non-empty password, encoded as UTF-8.
            salt: Exactly 16 bytes, from :func:`generate_salt`.

        Returns:
            The 32-byte master key.

        Raises:
            InvalidInputError: If the password is empty or the salt is not 16
                bytes.
            EncodingError: If the password holds a lone surrogate and cannot
                be encoded as UTF-8.
            KeyDerivationError: If the key-derivation backend fails.
        """
        if not password:
            raise InvalidInputError("password must not be empty")
        if len(salt) != SALT_LEN:
            raise InvalidInputError(f"salt must be exactly {SALT_LEN} bytes")
        try:
            encoded = password.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EncodingError("password is not valid UTF-8") from exc
        return self._kdf.derive_master(encoded, salt)

    def encrypt_with_key(self, key: bytes, plaintext: str) -> str:
        """Encrypt text into a base64 data blob under a fresh random nonce.

        Args:
            key: The 32-byte master key.
            plaintext: The text to encrypt, at most ``MAX_PLAINTEXT_LEN`` bytes
                in UTF-8.

        Returns:
            The blob, in padded standard base64.

        Raises:
            InvalidInputError: If the key is not 32 bytes or the text is too
                long. The key is checked first.
            EncodingError: If the text holds a lone surrogate.
            CipherError: If no nonce can be drawn or the cipher fails.
        """
        if len(key) != KEY_LEN:
            raise InvalidInputError(_KEY_LEN_MESSAGE)
        try:
            data = plaintext.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EncodingError("plaintext is not valid UTF-8") from exc
        return self._encrypt_bytes(key, data, _AAD_PURPOSE_DATA, b"")

    def decrypt_with_key(self, key: bytes, blob: str) -> str:
        """Verify and decrypt a data blob back to its text.

        Args:
            key: The 32-byte master key the blob was encrypted under.
            blob: The base64 blob.

        Returns:
            The original text.

        Raises:
            InvalidInputError: If the key is not 32 bytes, the input is too
                large, or the blob is malformed or of another version.
            EncodingError: If the base64 is not canonical, or the decrypted
                bytes are not UTF-8.
            CipherError: If authentication fails: wrong key, a blob of the
                envelope purpose, or any tampering.
        """
        plaintext = self._decrypt_bytes(key, blob, _AAD_PURPOSE_DATA, b"")
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            detail = _utf8_error_detail(exc)
            raise EncodingError(
                f"decrypted plaintext is not valid UTF-8: {detail}"
            ) from exc

    def wrap_key(self, kek: bytes, salt: bytes, key_material: bytes) -> str:
        """Wrap key material under a key-encryption key, bound to a salt.

        The salt is authenticated as associated data and not stored in the
        blob, so the same salt is needed to unwrap.

        Args:
            kek: The 32-byte key-encryption key.
            salt: The context the wrapped key is bound to, of any length.
            key_material: The bytes to wrap, typically a DEK.

        Returns:
            The wrapped key, in padded standard base64.

        Raises:
            InvalidInputError: If the KEK is not 32 bytes or the material is
                longer than ``MAX_PLAINTEXT_LEN``.
            CipherError: If no nonce can be drawn or the cipher fails.
        """
        return self._encrypt_bytes(kek, key_material, _AAD_PURPOSE_ENVELOPE, salt)

    def unwrap_key(self, kek: bytes, salt: bytes, wrapped: str) -> bytes:
        """Verify and unwrap key material wrapped by :meth:`wrap_key`.

        Args:
            kek: The 32-byte key-encryption key.
            salt: The salt the material was wrapped with.
            wrapped: The base64 wrapped key.

        Returns:
            The key material.

        Raises:
            InvalidInputError: As for :meth:`decrypt_with_key`.
            EncodingError: If the base64 is not canonical.
            CipherError: If authentication fails: wrong KEK, wrong salt, a data
                blob, or any tampering.
        """
        return self._decrypt_bytes(kek, wrapped, _AAD_PURPOSE_ENVELOPE, salt)

    def rewrap(
        self,
        old_kek: bytes,
        old_salt: bytes,
        new_kek: bytes,
        new_salt: bytes,
        blob: str,
    ) -> str:
        """Move wrapped key material to a new KEK and salt.

        Args:
            old_kek: The KEK the blob is wrapped under now.
            old_salt: The salt it is bound to now.
            new_kek: The KEK to wrap it under.
            new_salt: The salt to bind it to.
            blob: The current wrapped key.

        Returns:
            The material wrapped for the new context, under a fresh nonce.

        Raises:
            CryptoVaultError: Any error of :meth:`unwrap_key` for the old
                context, or of :meth:`wrap_key` for the new one.
        """
        dek = self.unwrap_key(old_kek, old_salt, blob)
        return self.wrap_key(new_kek, new_salt, dek)

    def _encrypt_bytes(
        self, key: bytes, data: bytes, purpose: int, aad_extra: bytes
    ) -> str:
        """Seal bytes into a blob of the given purpose.

        Args:
            key: The 32-byte master key.
            data: The plaintext bytes.
            purpose: ``_AAD_PURPOSE_DATA`` or ``_AAD_PURPOSE_ENVELOPE``.
            aad_extra: Bytes appended to the AAD (the salt for envelopes).

        Returns:
            ``base64(fec.encode(header ‖ nonce ‖ ciphertext ‖ tag))``.

        Raises:
            InvalidInputError: If the key is not 32 bytes or ``data`` is longer
                than ``MAX_PLAINTEXT_LEN``.
            CipherError: If no nonce can be drawn or the cipher fails.
        """
        if len(key) != KEY_LEN:
            raise InvalidInputError(_KEY_LEN_MESSAGE)
        if len(data) > MAX_PLAINTEXT_LEN:
            raise InvalidInputError("plaintext exceeds maximum size")
        header = _build_header(len(data))
        aad = bytes([purpose]) + header + aad_extra
        nonce = sample_nonce()
        sealed = self._cipher.encrypt(expand_aead_key(key), nonce, aad, data)
        blob = self._fec.encode(header + nonce + sealed)
        return base64.b64encode(blob).decode("ascii")

    def _decrypt_bytes(
        self, key: bytes, blob: str, purpose: int, aad_extra: bytes
    ) -> bytes:
        """Open a blob of the given purpose, checking in the crate's fixed order.

        The order is part of the contract: key length, base64 length (before
        decoding), canonical base64, decoded length against this vault's cap,
        blob structure, then authentication. Every check before the last runs
        before any AEAD work.

        Args:
            key: The 32-byte master key.
            blob: The base64 blob.
            purpose: ``_AAD_PURPOSE_DATA`` or ``_AAD_PURPOSE_ENVELOPE``.
            aad_extra: Bytes appended to the AAD (the salt for envelopes).

        Returns:
            The plaintext bytes.

        Raises:
            InvalidInputError: Key length, size caps, malformed blob, version.
            EncodingError: Non-canonical base64.
            CipherError: The tag does not verify.
        """
        if len(key) != KEY_LEN:
            raise InvalidInputError(_KEY_LEN_MESSAGE)
        if _utf8_len(blob) > MAX_B64_LEN:
            raise InvalidInputError(_TOO_LARGE_MESSAGE)
        received = _decode_base64(blob)
        if len(received) > self._max_blob_len:
            raise InvalidInputError(_TOO_LARGE_MESSAGE)
        _, plaintext_len, body = decode_blob(self._fec, received)
        # The AAD is rebuilt from the recovered header, so any change to it
        # fails authentication.
        aad = bytes([purpose]) + _build_header(plaintext_len) + aad_extra
        nonce, sealed = body[:NONCE_LEN], body[NONCE_LEN:]
        return self._cipher.decrypt(expand_aead_key(key), nonce, aad, sealed)
