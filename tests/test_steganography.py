"""
Integration tests for SteganographyEngine.
"""

import os
import pytest
import numpy as np
from PIL import Image

from src.steganography import SteganographyEngine
from src.validation import ValidationError


def _create_png(tmp_path, width=200, height=200, name="cover.png"):
    """Create a simple RGB PNG image for testing."""
    arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    img = Image.fromarray(arr, "RGB")
    path = str(tmp_path / name)
    img.save(path)
    return path


@pytest.fixture
def engine():
    return SteganographyEngine()


@pytest.fixture
def cover(tmp_path):
    return _create_png(tmp_path)


@pytest.fixture
def stego(tmp_path):
    return str(tmp_path / "stego.png")


# --------------------------------------------------------------------------- #
#  Basic embed / extract
# --------------------------------------------------------------------------- #

class TestBasicEmbedExtract:
    def test_plaintext_roundtrip(self, engine, cover, stego):
        engine.embed(cover, stego, "Hello, World!")
        msg = engine.extract(stego)
        assert msg == "Hello, World!"

    def test_with_password(self, engine, cover, stego):
        engine.embed(cover, stego, "Secret message", password="P@ssword1")
        msg = engine.extract(stego, password="P@ssword1")
        assert msg == "Secret message"

    def test_with_steg_key(self, engine, cover, stego):
        engine.embed(cover, stego, "Hidden", steg_key="MyStegKey1")
        msg = engine.extract(stego, steg_key="MyStegKey1")
        assert msg == "Hidden"

    def test_with_password_and_steg_key(self, engine, cover, stego):
        engine.embed(
            cover, stego, "Double protected",
            password="P@ssword1",
            steg_key="MyStegKey1",
        )
        msg = engine.extract(stego, password="P@ssword1", steg_key="MyStegKey1")
        assert msg == "Double protected"

    def test_unicode_message(self, engine, cover, stego):
        msg_in = "こんにちは世界 🌍"
        engine.embed(cover, stego, msg_in)
        assert engine.extract(stego) == msg_in

    def test_long_message(self, engine, tmp_path, stego):
        # Create a bigger image to fit the message
        big_cover = _create_png(tmp_path, width=500, height=500, name="big.png")
        long_msg = "A" * 5000
        engine.embed(big_cover, stego, long_msg)
        assert engine.extract(stego) == long_msg

    def test_multiline_message(self, engine, cover, stego):
        msg = "Line 1\nLine 2\nLine 3"
        engine.embed(cover, stego, msg)
        assert engine.extract(stego) == msg

    def test_bmp_format(self, engine, tmp_path):
        arr = np.random.randint(0, 256, (200, 200, 3), dtype=np.uint8)
        cover_bmp = str(tmp_path / "cover.bmp")
        stego_bmp = str(tmp_path / "stego.bmp")
        Image.fromarray(arr, "RGB").save(cover_bmp)
        engine.embed(cover_bmp, stego_bmp, "BMP test")
        assert engine.extract(stego_bmp) == "BMP test"

    def test_tiff_format(self, engine, tmp_path):
        arr = np.random.randint(0, 256, (200, 200, 3), dtype=np.uint8)
        cover_tiff = str(tmp_path / "cover.tiff")
        stego_tiff = str(tmp_path / "stego.tiff")
        Image.fromarray(arr, "RGB").save(cover_tiff)
        engine.embed(cover_tiff, stego_tiff, "TIFF test")
        assert engine.extract(stego_tiff) == "TIFF test"


# --------------------------------------------------------------------------- #
#  Security checks
# --------------------------------------------------------------------------- #

class TestSecurityChecks:
    def test_wrong_password_raises(self, engine, cover, stego):
        engine.embed(cover, stego, "Secret", password="Correct1!")
        with pytest.raises(ValidationError):
            engine.extract(stego, password="Wrong123!")

    def test_wrong_steg_key_extracts_garbage(self, engine, cover, stego):
        """Wrong steg_key uses different pixel order → should fail or return garbage."""
        engine.embed(cover, stego, "Hidden", steg_key="RightKey1")
        with pytest.raises((ValidationError, UnicodeDecodeError, Exception)):
            engine.extract(stego, steg_key="WrongKey1")

    def test_no_password_no_encryption(self, engine, cover, stego):
        """Without a password, extraction should still work (plaintext embedding)."""
        engine.embed(cover, stego, "plain")
        # But providing a password on extract should fail (wrong decryption)
        with pytest.raises((ValidationError, Exception)):
            engine.extract(stego, password="APassword1!")

    def test_stego_image_differs_from_cover(self, engine, cover, stego):
        """Embedding must actually change the image."""
        from src.image_handler import ImageHandler
        h = ImageHandler()
        cover_arr, _ = h.load_image(cover)
        engine.embed(cover, stego, "change me")
        stego_arr, _ = h.load_image(stego)
        assert not np.array_equal(cover_arr, stego_arr)


# --------------------------------------------------------------------------- #
#  Capacity and validation
# --------------------------------------------------------------------------- #

class TestCapacity:
    def test_get_capacity_returns_positive(self, engine, cover):
        cap = engine.get_capacity(cover)
        assert cap > 0

    def test_message_too_large_raises(self, engine, tmp_path):
        # Tiny 5×5 image
        tiny = str(tmp_path / "tiny.png")
        Image.fromarray(np.zeros((5, 5, 3), dtype=np.uint8), "RGB").save(tiny)
        stego = str(tmp_path / "s.png")
        with pytest.raises(ValidationError, match="too large"):
            engine.embed(tiny, stego, "A" * 1000)

    def test_invalid_input_format_raises(self, engine, tmp_path, stego):
        jpg = str(tmp_path / "cover.jpg")
        Image.fromarray(np.zeros((100, 100, 3), dtype=np.uint8)).save(jpg, "JPEG")
        with pytest.raises(ValidationError):
            engine.embed(jpg, stego, "test")

    def test_missing_input_image_raises(self, engine, stego):
        with pytest.raises((ValidationError, FileNotFoundError)):
            engine.embed("/no/such/file.png", stego, "test")


# --------------------------------------------------------------------------- #
#  bits_per_channel=2
# --------------------------------------------------------------------------- #

class TestBits2:
    def test_roundtrip_2bpc(self, tmp_path):
        engine2 = SteganographyEngine(bits_per_channel=2)
        cover = _create_png(tmp_path, width=100, height=100, name="c2.png")
        stego = str(tmp_path / "s2.png")
        engine2.embed(cover, stego, "Two-bit message")
        assert engine2.extract(stego) == "Two-bit message"

    def test_invalid_bpc_raises(self):
        with pytest.raises(ValueError):
            SteganographyEngine(bits_per_channel=3)
