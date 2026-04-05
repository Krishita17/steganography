"""
Tests for the EncryptionManager module.
"""

import pytest
from src.encryption import EncryptionManager, SALT_SIZE, IV_SIZE, HMAC_SIZE, HEADER_SIZE


@pytest.fixture
def enc():
    return EncryptionManager()


class TestDeriveKey:
    def test_returns_32_bytes(self, enc):
        import os
        salt = os.urandom(32)
        key = enc.derive_key("password123", salt)
        assert len(key) == 32

    def test_deterministic(self, enc):
        salt = b"a" * 32
        k1 = enc.derive_key("password", salt)
        k2 = enc.derive_key("password", salt)
        assert k1 == k2

    def test_different_passwords_differ(self, enc):
        salt = b"b" * 32
        assert enc.derive_key("pass1", salt) != enc.derive_key("pass2", salt)

    def test_different_salts_differ(self, enc):
        k1 = enc.derive_key("password", b"a" * 32)
        k2 = enc.derive_key("password", b"b" * 32)
        assert k1 != k2

    def test_empty_password_raises(self, enc):
        with pytest.raises(ValueError):
            enc.derive_key("", b"a" * 32)

    def test_short_salt_raises(self, enc):
        with pytest.raises(ValueError):
            enc.derive_key("password", b"tooshort")


class TestHMAC:
    def test_verify_correct_tag(self, enc):
        key = b"k" * 32
        data = b"hello"
        tag = enc.compute_hmac(key, data)
        assert enc.verify_hmac(key, data, tag)

    def test_verify_wrong_tag(self, enc):
        key = b"k" * 32
        data = b"hello"
        bad_tag = b"x" * 32
        assert not enc.verify_hmac(key, data, bad_tag)

    def test_verify_tampered_data(self, enc):
        key = b"k" * 32
        tag = enc.compute_hmac(key, b"original")
        assert not enc.verify_hmac(key, b"tampered", tag)


class TestEncryptDecrypt:
    def test_roundtrip(self, enc):
        plaintext = b"Hello, steganography!"
        blob = enc.encrypt(plaintext, "StrongPass1!")
        result = enc.decrypt(blob, "StrongPass1!")
        assert result == plaintext

    def test_empty_plaintext(self, enc):
        blob = enc.encrypt(b"", "StrongPass1!")
        assert enc.decrypt(blob, "StrongPass1!") == b""

    def test_large_plaintext(self, enc):
        data = b"X" * 100_000
        blob = enc.encrypt(data, "StrongPass1!")
        assert enc.decrypt(blob, "StrongPass1!") == data

    def test_wrong_password_raises(self, enc):
        blob = enc.encrypt(b"secret", "CorrectPass1!")
        with pytest.raises(ValueError, match="HMAC"):
            enc.decrypt(blob, "WrongPass1!")

    def test_tampered_ciphertext_raises(self, enc):
        blob = enc.encrypt(b"secret", "Pass1234!")
        tampered = bytearray(blob)
        # Flip a bit in the ciphertext area
        tampered[HEADER_SIZE + 5] ^= 0xFF
        with pytest.raises(ValueError):
            enc.decrypt(bytes(tampered), "Pass1234!")

    def test_truncated_blob_raises(self, enc):
        with pytest.raises(ValueError):
            enc.decrypt(b"tooshort", "Pass1234!")

    def test_non_bytes_plaintext_raises(self, enc):
        with pytest.raises(TypeError):
            enc.encrypt("not bytes", "Pass1234!")

    def test_blob_has_correct_minimum_size(self, enc):
        blob = enc.encrypt(b"a", "Pass1234!")
        assert len(blob) >= HEADER_SIZE

    def test_encryption_produces_different_blobs(self, enc):
        # Encryption is randomised (different salts/IVs each time)
        b1 = enc.encrypt(b"same", "Pass1234!")
        b2 = enc.encrypt(b"same", "Pass1234!")
        assert b1 != b2

    def test_unicode_password(self, enc):
        pt = b"unicode test"
        password = "pässwörD1!"
        blob = enc.encrypt(pt, password)
        assert enc.decrypt(blob, password) == pt


class TestStegKey:
    def test_derive_steg_key_returns_32_bytes(self):
        key = EncryptionManager.derive_steg_key("mykey", b"salt1234")
        assert len(key) == 32

    def test_derive_steg_key_deterministic(self):
        k1 = EncryptionManager.derive_steg_key("key", b"salt")
        k2 = EncryptionManager.derive_steg_key("key", b"salt")
        assert k1 == k2

    def test_derive_steg_key_different_inputs_differ(self):
        k1 = EncryptionManager.derive_steg_key("key1", b"salt")
        k2 = EncryptionManager.derive_steg_key("key2", b"salt")
        assert k1 != k2
