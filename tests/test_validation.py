"""
Tests for the Validator module.
"""

import pytest
import numpy as np

from src.validation import Validator, ValidationError


@pytest.fixture
def v():
    return Validator()


class TestValidateInputPath:
    def test_valid_file(self, v, tmp_path):
        f = tmp_path / "test.png"
        f.write_bytes(b"data")
        assert v.validate_input_path(str(f))

    def test_nonexistent(self, v):
        with pytest.raises(ValidationError, match="not found"):
            v.validate_input_path("/no/such/file.png")

    def test_empty_string(self, v):
        with pytest.raises(ValidationError):
            v.validate_input_path("")

    def test_none_raises(self, v):
        with pytest.raises(ValidationError):
            v.validate_input_path(None)

    def test_directory_raises(self, v, tmp_path):
        with pytest.raises(ValidationError, match="not a file"):
            v.validate_input_path(str(tmp_path))


class TestValidateOutputPath:
    def test_valid_output_path(self, v, tmp_path):
        out = str(tmp_path / "out.png")
        assert v.validate_output_path(out)

    def test_nonexistent_parent_raises(self, v):
        with pytest.raises(ValidationError, match="directory does not exist"):
            v.validate_output_path("/no/such/dir/out.png")

    def test_empty_string_raises(self, v):
        with pytest.raises(ValidationError):
            v.validate_output_path("")


class TestValidateImageFormat:
    @pytest.mark.parametrize("ext", [".png", ".bmp", ".tiff", ".tif"])
    def test_supported_formats(self, v, ext):
        assert v.validate_image_format(f"image{ext}")

    @pytest.mark.parametrize("ext", [".jpg", ".jpeg", ".gif", ".webp"])
    def test_unsupported_formats(self, v, ext):
        with pytest.raises(ValidationError, match="Unsupported image format"):
            v.validate_image_format(f"image{ext}")


class TestValidateMessage:
    def test_valid_message(self, v):
        assert v.validate_message("Hello, World!")

    def test_empty_message_raises(self, v):
        with pytest.raises(ValidationError, match="empty"):
            v.validate_message("")

    def test_non_string_raises(self, v):
        with pytest.raises(ValidationError, match="string"):
            v.validate_message(12345)

    def test_unicode_message(self, v):
        assert v.validate_message("こんにちは世界")

    def test_oversized_message_raises(self, v):
        big = "x" * (64 * 1024 * 1024 + 1)
        with pytest.raises(ValidationError, match="maximum size"):
            v.validate_message(big)


class TestValidateCapacity:
    def test_fits(self, v):
        arr = np.zeros((100, 100, 3), dtype=np.uint8)
        assert v.validate_capacity(10, arr)

    def test_too_large_raises(self, v):
        arr = np.zeros((2, 2, 3), dtype=np.uint8)  # tiny image
        with pytest.raises(ValidationError, match="too large"):
            v.validate_capacity(1000, arr)

    def test_exact_capacity(self, v):
        arr = np.zeros((100, 100, 3), dtype=np.uint8)
        # capacity = (30000 - 32) // 8 = 3746 bytes
        cap = (arr.size * 1 - 32) // 8
        assert v.validate_capacity(cap, arr)


class TestValidatePassword:
    def test_valid_password(self, v):
        assert v.validate_password("StrongPass123!")

    def test_too_short_raises(self, v):
        with pytest.raises(ValidationError, match="at least 8"):
            v.validate_password("short")

    def test_exactly_8_chars(self, v):
        assert v.validate_password("12345678")

    def test_non_string_raises(self, v):
        with pytest.raises(ValidationError):
            v.validate_password(None)


class TestValidateOptionalPassword:
    def test_none_allowed(self, v):
        assert v.validate_optional_password(None)

    def test_empty_string_allowed(self, v):
        assert v.validate_optional_password("")

    def test_valid_password_allowed(self, v):
        assert v.validate_optional_password("ValidPass1!")

    def test_too_short_still_raises(self, v):
        with pytest.raises(ValidationError):
            v.validate_optional_password("short")
