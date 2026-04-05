"""
Image Handler Module
====================
Loads, validates, and saves images for steganographic operations.
Supports PNG, BMP, and TIFF (lossless) formats.
"""

import logging
from pathlib import Path
from typing import Tuple

import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = {".png", ".bmp", ".tiff", ".tif"}
SUPPORTED_MODES = {"RGB", "RGBA", "L"}


class ImageHandler:
    """
    Handles image I/O and pixel-level access for steganography.

    Attributes
    ----------
    SUPPORTED_FORMATS : set[str]
        Lossless formats that preserve LSB information.
    """

    SUPPORTED_FORMATS = SUPPORTED_FORMATS

    # ------------------------------------------------------------------ #
    #  Load / Save
    # ------------------------------------------------------------------ #

    def load_image(self, path: str) -> Tuple[np.ndarray, str]:
        """
        Load an image from *path* and return a NumPy array plus the mode.

        Parameters
        ----------
        path : str
            Path to the cover image.

        Returns
        -------
        Tuple[np.ndarray, str]
            ``(pixel_array, mode)`` where *mode* is e.g. ``"RGB"``.

        Raises
        ------
        FileNotFoundError
            If *path* does not exist.
        ValueError
            If the format or mode is not supported.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Image not found: {path}")

        suffix = p.suffix.lower()
        if suffix not in SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format '{suffix}'. "
                f"Supported: {sorted(SUPPORTED_FORMATS)}"
            )

        img = Image.open(path)

        # Ensure a stable, predictable mode
        if img.mode not in SUPPORTED_MODES:
            img = img.convert("RGB")
            logger.debug("Converted image from '%s' to 'RGB'.", img.mode)

        arr = np.array(img, dtype=np.uint8)
        logger.info(
            "Loaded image '%s': shape=%s, mode=%s.", path, arr.shape, img.mode
        )
        return arr, img.mode

    def save_image(self, arr: np.ndarray, mode: str, path: str) -> None:
        """
        Save a NumPy pixel array as a lossless image.

        Parameters
        ----------
        arr  : np.ndarray
        mode : str   Image mode (``"RGB"``, ``"RGBA"``, or ``"L"``).
        path : str   Output path.  The file extension must be lossless.
        """
        p = Path(path)
        suffix = p.suffix.lower()
        if suffix not in SUPPORTED_FORMATS:
            raise ValueError(
                f"Output format '{suffix}' is not lossless. "
                f"Use one of {sorted(SUPPORTED_FORMATS)}."
            )

        img = Image.fromarray(arr, mode=mode)
        img.save(path)
        logger.info("Saved stego image to '%s'.", path)

    # ------------------------------------------------------------------ #
    #  Capacity
    # ------------------------------------------------------------------ #

    def calculate_capacity(self, arr: np.ndarray, bits_per_channel: int = 1) -> int:
        """
        Return the maximum number of *payload bytes* that can be hidden.

        Parameters
        ----------
        arr              : np.ndarray  Pixel array.
        bits_per_channel : int         LSBs used per channel (default 1).

        Returns
        -------
        int
            Number of payload bytes available.
        """
        total_bits = arr.size * bits_per_channel
        # Reserve 4 bytes (32 bits) for the length header
        usable_bits = total_bits - 32
        return max(0, usable_bits // 8)

    # ------------------------------------------------------------------ #
    #  Pixel iterators
    # ------------------------------------------------------------------ #

    def iter_pixels(
        self,
        arr: np.ndarray,
        indices: "np.ndarray | None" = None,
    ):
        """
        Yield ``(row, col, channel)`` tuples in a deterministic order.

        If *indices* is given (a 1-D array of flat pixel indices) they are
        used instead of sequential order, enabling steganographic-key
        permutation.

        Parameters
        ----------
        arr     : np.ndarray   Shape ``(H, W, C)`` or ``(H, W)``.
        indices : ndarray      Optional permuted flat-index order.
        """
        if arr.ndim == 2:
            h, w = arr.shape
            channels = 1
        else:
            h, w, channels = arr.shape

        if indices is None:
            for r in range(h):
                for c in range(w):
                    for ch in range(channels):
                        yield r, c, ch
        else:
            for flat in indices:
                r, c = divmod(int(flat), w)
                for ch in range(channels):
                    yield r, c, ch

    def get_pixel_indices(
        self, arr: np.ndarray, seed: "bytes | None" = None
    ) -> np.ndarray:
        """
        Return an array of flat pixel indices, optionally shuffled with *seed*.

        Parameters
        ----------
        arr  : np.ndarray
        seed : bytes | None   If given, used to seed a NumPy RNG for shuffling.

        Returns
        -------
        np.ndarray
            1-D array of flat pixel indices (length = H × W).
        """
        if arr.ndim == 2:
            h, w = arr.shape
        else:
            h, w = arr.shape[:2]

        indices = np.arange(h * w, dtype=np.int64)

        if seed is not None:
            seed_int = int.from_bytes(seed[:4], "big")
            rng = np.random.default_rng(seed_int)
            rng.shuffle(indices)
            logger.debug("Pixel indices shuffled with steganographic key.")

        return indices
