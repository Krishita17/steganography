"""
Tests for the ImageHandler module.
"""

import os
import tempfile
import pytest
import numpy as np
from PIL import Image

from src.image_handler import ImageHandler


@pytest.fixture
def handler():
    return ImageHandler()


def _make_image(tmp_path, width=100, height=80, mode="RGB", fmt="PNG"):
    arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    if mode == "L":
        arr = arr[:, :, 0]
    img = Image.fromarray(arr, mode=mode)
    ext = fmt.lower()
    path = str(tmp_path / f"test.{ext}")
    img.save(path)
    return path, arr


class TestLoadImage:
    def test_load_png(self, handler, tmp_path):
        path, _ = _make_image(tmp_path)
        arr, mode = handler.load_image(path)
        assert isinstance(arr, np.ndarray)
        assert mode in ("RGB", "RGBA", "L")

    def test_load_bmp(self, handler, tmp_path):
        path, _ = _make_image(tmp_path, fmt="BMP")
        arr, mode = handler.load_image(path)
        assert arr.shape[2] == 3

    def test_load_tiff(self, handler, tmp_path):
        path, _ = _make_image(tmp_path, fmt="TIFF")
        arr, mode = handler.load_image(path)
        assert arr is not None

    def test_file_not_found(self, handler):
        with pytest.raises(FileNotFoundError):
            handler.load_image("/nonexistent/path/img.png")

    def test_unsupported_format(self, handler, tmp_path):
        # Create a JPEG
        img = Image.fromarray(np.zeros((10, 10, 3), dtype=np.uint8), "RGB")
        p = str(tmp_path / "test.jpg")
        img.save(p, "JPEG")
        with pytest.raises(ValueError, match="Unsupported format"):
            handler.load_image(p)

    def test_shape_preserved(self, handler, tmp_path):
        path, arr = _make_image(tmp_path, width=64, height=48)
        loaded, _ = handler.load_image(path)
        assert loaded.shape == (48, 64, 3)


class TestSaveImage:
    def test_save_png(self, handler, tmp_path):
        arr = np.zeros((20, 20, 3), dtype=np.uint8)
        out = str(tmp_path / "out.png")
        handler.save_image(arr, "RGB", out)
        assert os.path.exists(out)

    def test_save_bmp(self, handler, tmp_path):
        arr = np.zeros((20, 20, 3), dtype=np.uint8)
        out = str(tmp_path / "out.bmp")
        handler.save_image(arr, "RGB", out)
        assert os.path.exists(out)

    def test_save_tiff(self, handler, tmp_path):
        arr = np.zeros((20, 20, 3), dtype=np.uint8)
        out = str(tmp_path / "out.tiff")
        handler.save_image(arr, "RGB", out)
        assert os.path.exists(out)

    def test_save_unsupported_format_raises(self, handler, tmp_path):
        arr = np.zeros((20, 20, 3), dtype=np.uint8)
        out = str(tmp_path / "out.jpg")
        with pytest.raises(ValueError, match="not lossless"):
            handler.save_image(arr, "RGB", out)

    def test_roundtrip_preserves_pixels(self, handler, tmp_path):
        arr = np.arange(0, 75, dtype=np.uint8).reshape(5, 5, 3)
        out = str(tmp_path / "rt.png")
        handler.save_image(arr, "RGB", out)
        loaded, _ = handler.load_image(out)
        np.testing.assert_array_equal(arr, loaded)


class TestCalculateCapacity:
    def test_rgb_100x100(self, handler):
        arr = np.zeros((100, 100, 3), dtype=np.uint8)
        # 100*100*3 = 30000 bits → 30000//8 - 4 bytes overhead = 3750 - 4 = 3746? 
        # Actually: (30000 - 32) // 8 = 29968 // 8 = 3746
        cap = handler.calculate_capacity(arr, bits_per_channel=1)
        assert cap == 3746

    def test_capacity_scales_with_size(self, handler):
        small = np.zeros((10, 10, 3), dtype=np.uint8)
        large = np.zeros((100, 100, 3), dtype=np.uint8)
        assert handler.calculate_capacity(large) > handler.calculate_capacity(small)

    def test_bits2_doubles_capacity(self, handler):
        arr = np.zeros((100, 100, 3), dtype=np.uint8)
        cap1 = handler.calculate_capacity(arr, bits_per_channel=1)
        cap2 = handler.calculate_capacity(arr, bits_per_channel=2)
        assert cap2 == pytest.approx(cap1 * 2, abs=10)


class TestPixelIndices:
    def test_sequential_length(self, handler):
        arr = np.zeros((10, 10, 3), dtype=np.uint8)
        idx = handler.get_pixel_indices(arr)
        assert len(idx) == 100

    def test_shuffled_length(self, handler):
        arr = np.zeros((10, 10, 3), dtype=np.uint8)
        idx = handler.get_pixel_indices(arr, seed=b"\x01\x02\x03\x04" * 8)
        assert len(idx) == 100

    def test_shuffled_contains_all_values(self, handler):
        arr = np.zeros((10, 10, 3), dtype=np.uint8)
        idx = handler.get_pixel_indices(arr, seed=b"\xAB\xCD\xEF\x01" * 8)
        assert sorted(idx.tolist()) == list(range(100))

    def test_different_seeds_different_order(self, handler):
        arr = np.zeros((20, 20, 3), dtype=np.uint8)
        idx1 = handler.get_pixel_indices(arr, seed=b"\x01" * 32)
        idx2 = handler.get_pixel_indices(arr, seed=b"\x02" * 32)
        assert not np.array_equal(idx1, idx2)

    def test_same_seed_same_order(self, handler):
        arr = np.zeros((20, 20, 3), dtype=np.uint8)
        seed = b"\xDE\xAD\xBE\xEF" * 8
        idx1 = handler.get_pixel_indices(arr, seed=seed)
        idx2 = handler.get_pixel_indices(arr, seed=seed)
        np.testing.assert_array_equal(idx1, idx2)
