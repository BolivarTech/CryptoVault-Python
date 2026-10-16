# Author: Julian Bolivar
# Version: 0.1.0
# Date: 2026-10-16
"""``Aes256GcmSivCipher`` is AES-256-GCM-SIV with the crate's errors (CV-01)."""

import pytest
from cryptography.exceptions import InvalidTag

from cryptovault.cipher import Aes256GcmSivCipher
from cryptovault.error import CipherError

# RFC 8452, Appendix C.2 (AEAD_AES_256_GCM_SIV): key, nonce, aad, plaintext,
# ciphertext followed by the tag.
RFC8452_VECTORS = [
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "",
        "07f5f4169bbf55a8400cd47ea6fd400f",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "0100000000000000",
        "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
    ),
]


@pytest.mark.parametrize(
    ("key", "nonce", "aad", "plaintext", "sealed"), RFC8452_VECTORS
)
def test_encrypt_and_decrypt_reproduce_the_rfc_8452_vectors(
    key: str, nonce: str, aad: str, plaintext: str, sealed: str
) -> None:
    cipher = Aes256GcmSivCipher()
    args = (bytes.fromhex(key), bytes.fromhex(nonce), bytes.fromhex(aad))
    assert cipher.encrypt(*args, bytes.fromhex(plaintext)).hex() == sealed
    assert cipher.decrypt(*args, bytes.fromhex(sealed)).hex() == plaintext


def test_decrypt_rejects_a_flipped_tag_bit_with_the_crate_message() -> None:
    cipher = Aes256GcmSivCipher()
    key, nonce = bytes(32), bytes(12)
    sealed = bytearray(cipher.encrypt(key, nonce, b"aad", b"secret"))
    sealed[-1] ^= 0x01
    with pytest.raises(CipherError) as caught:
        cipher.decrypt(key, nonce, b"aad", bytes(sealed))
    assert str(caught.value) == "Cipher error: AES-256-GCM-SIV authentication failed"
    assert isinstance(caught.value.__cause__, InvalidTag)
