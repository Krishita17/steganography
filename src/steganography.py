"""
Steganography Engine
====================
Core LSB (Least Significant Bit) steganography engine.

Supports:
- AES-256-GCM encryption of the hidden payload (optional)
- HMAC-SHA256 integrity verification (via EncryptionManager)
- Steganographic-key pixel permutation (optional)
- PNG, BMP, TIFF cover images
- Capacity calculation before embedding

Wire format of the raw payload (before encryption)::

    length (4 bytes, big-endian uint32) | utf-8 message bytes

After optional encryption the blob is treated as raw bytes and embedded
bit-by-bit into the cover image starting from a configurable bit plane.
"""

import logging
import struct
from typing import Optional

import numpy as np

from .encryption import EncryptionManager
from .image_handler import ImageHandler
from .validation import ValidationError, Validator

logger = logging.getLogger(__name__)

# Number of LSBs used per channel (1 gives the best visual quality)
DEFAULT_BITS_PER_CHANNEL = 1


class SteganographyEngine:
    """
    High-level steganography interface.

    Parameters
    ----------
    bits_per_channel : int
        How many least-significant bits to use per colour channel.
        ``1`` (default) gives imperceptible changes; ``2`` doubles capacity
        at the cost of slightly more visible artefacts.

    Example
    -------
    >>> engine = SteganographyEngine()
    >>> engine.embed(
    ...     input_image="cover.png",
    ...     output_image="stego.png",
    ...     message="Top secret",
    ...     password="s3cur3P@ss",
    ... )
    >>> msg = engine.extract(input_image="stego.png", password="s3cur3P@ss")
    >>> print(msg)
    Top secret
    """

    def __init__(self, bits_per_channel: int = DEFAULT_BITS_PER_CHANNEL) -> None:
        if bits_per_channel not in (1, 2):
            raise ValueError("bits_per_channel must be 1 or 2.")
        self.bits_per_channel = bits_per_channel
        self._enc = EncryptionManager()
        self._img = ImageHandler()
        self._val = Validator()

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def embed(
        self,
        input_image: str,
        output_image: str,
        message: str,
        password: Optional[str] = None,
        steg_key: Optional[str] = None,
    ) -> int:
        """
        Embed *message* into *input_image* and write the result to
        *output_image*.

        Parameters
        ----------
        input_image  : str   Path to the cover image (PNG / BMP / TIFF).
        output_image : str   Path for the stego image (must be lossless).
        message      : str   Plaintext message to hide.
        password     : str | None
            If provided the message is encrypted with AES-256-GCM before
            embedding.  Must be ≥ 8 characters.
        steg_key     : str | None
            If provided, pixels are visited in a key-derived permuted order
            rather than sequentially, adding an extra layer of obscurity.

        Returns
        -------
        int
            Number of bytes embedded.

        Raises
        ------
        ValidationError
            On invalid inputs or insufficient capacity.
        """
        # --- validate inputs -------------------------------------------
        self._val.validate_input_path(input_image)
        self._val.validate_image_format(input_image)
        self._val.validate_output_path(output_image)
        self._val.validate_image_format(output_image)
        self._val.validate_message(message)
        self._val.validate_optional_password(password, field="password")
        self._val.validate_optional_password(steg_key, field="steg_key")

        # --- load image ------------------------------------------------
        arr, mode = self._img.load_image(input_image)

        # --- prepare payload -------------------------------------------
        plaintext = message.encode("utf-8")

        if password:
            payload = self._enc.encrypt(plaintext, password)
            logger.info("Message encrypted with AES-256-GCM.")
        else:
            payload = plaintext

        # 4-byte length prefix
        length_prefix = struct.pack(">I", len(payload))
        data_bytes = length_prefix + payload

        # --- capacity check --------------------------------------------
        self._val.validate_capacity(
            len(data_bytes), arr, self.bits_per_channel
        )

        # --- pixel order -----------------------------------------------
        seed = None
        if steg_key:
            salt = b"steg_key_salt_v1"   # deterministic, per-project salt
            seed = self._enc.derive_steg_key(steg_key, salt)

        indices = self._img.get_pixel_indices(arr, seed=seed)

        # --- embed ----------------------------------------------------- #
        arr = arr.copy()
        self._embed_bits(arr, data_bytes, indices)

        # --- save -------------------------------------------------------
        self._img.save_image(arr, mode, output_image)
        logger.info(
            "Embedded %d bytes into '%s' → '%s'.",
            len(data_bytes),
            input_image,
            output_image,
        )
        return len(data_bytes)

    def extract(
        self,
        input_image: str,
        password: Optional[str] = None,
        steg_key: Optional[str] = None,
    ) -> str:
        """
        Extract a hidden message from *input_image*.

        Parameters
        ----------
        input_image : str   Path to the stego image.
        password    : str | None
            Decryption password (must match the one used during embedding).
        steg_key    : str | None
            Steganographic key (must match the one used during embedding).

        Returns
        -------
        str
            The hidden plaintext message.

        Raises
        ------
        ValidationError
            If inputs are invalid or decryption / integrity checks fail.
        """
        self._val.validate_input_path(input_image)
        self._val.validate_image_format(input_image)
        self._val.validate_optional_password(password, field="password")
        self._val.validate_optional_password(steg_key, field="steg_key")

        arr, _ = self._img.load_image(input_image)

        seed = None
        if steg_key:
            salt = b"steg_key_salt_v1"
            seed = self._enc.derive_steg_key(steg_key, salt)

        indices = self._img.get_pixel_indices(arr, seed=seed)

        data_bytes = self._extract_bits(arr, indices)

        if password:
            try:
                plaintext = self._enc.decrypt(data_bytes, password)
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            logger.info("Message decrypted successfully.")
        else:
            plaintext = data_bytes

        try:
            message = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError(
                "Could not decode message as UTF-8. "
                "Wrong password or steg_key, or no message embedded."
            ) from exc

        logger.info("Extracted message of %d characters.", len(message))
        return message

    def get_capacity(self, image_path: str) -> int:
        """
        Return the maximum number of plaintext bytes that can be embedded.

        Parameters
        ----------
        image_path : str

        Returns
        -------
        int
        """
        self._val.validate_input_path(image_path)
        self._val.validate_image_format(image_path)
        arr, _ = self._img.load_image(image_path)
        return self._img.calculate_capacity(arr, self.bits_per_channel)

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    def _embed_bits(
        self,
        arr: np.ndarray,
        data: bytes,
        indices: np.ndarray,
    ) -> None:
        """Embed *data* into *arr* in-place using the given pixel order."""
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        total_bits = len(bits)
        bpc = self.bits_per_channel
        lsb_mask = (1 << bpc) - 1
        upper_mask = 0xFF ^ lsb_mask

        flat = arr.reshape(-1, arr.shape[-1]) if arr.ndim == 3 else arr.reshape(-1, 1)
        channels = flat.shape[1]
        bit_idx = 0

        for pixel_flat in indices:
            if bit_idx >= total_bits:
                break
            for ch in range(channels):
                if bit_idx >= total_bits:
                    break
                # Extract `bpc` bits, padding with zeros if at the end
                end = bit_idx + bpc
                chunk = bits[bit_idx:end]
                if len(chunk) < bpc:
                    chunk = np.concatenate(
                        [np.zeros(bpc - len(chunk), dtype=np.uint8), chunk]
                    )
                # Pack those bits into a single integer value (0 .. 2^bpc-1)
                chunk_val = 0
                for b in chunk:
                    chunk_val = (chunk_val << 1) | int(b)

                flat[pixel_flat, ch] = (int(flat[pixel_flat, ch]) & upper_mask) | chunk_val
                bit_idx += bpc

    def _extract_bits(
        self,
        arr: np.ndarray,
        indices: np.ndarray,
    ) -> bytes:
        """
        Extract the payload bytes from *arr* in a single pass over *indices*.

        The first 32 bits encode the payload length (big-endian uint32).
        The following ``length * 8`` bits encode the payload.
        """
        bpc = self.bits_per_channel
        lsb_mask = (1 << bpc) - 1

        flat = arr.reshape(-1, arr.shape[-1]) if arr.ndim == 3 else arr.reshape(-1, 1)
        channels = flat.shape[1]

        raw_bits: list[int] = []
        length: int | None = None

        for pixel_flat in indices:
            # Stop once we have all the bits we need
            if length is not None and len(raw_bits) >= 32 + length * 8:
                break
            for ch in range(channels):
                if length is not None and len(raw_bits) >= 32 + length * 8:
                    break
                lsb_val = int(flat[pixel_flat, ch]) & lsb_mask
                # Decompose LSB value into individual bits (MSB first)
                for shift in range(bpc - 1, -1, -1):
                    raw_bits.append((lsb_val >> shift) & 1)

                # Once we have 32 bits, decode the length header
                if length is None and len(raw_bits) >= 32:
                    hdr = np.packbits(np.array(raw_bits[:32], dtype=np.uint8)).tobytes()
                    length = struct.unpack(">I", hdr)[0]
                    if length == 0 or length > 128 * 1024 * 1024:
                        raise ValidationError(
                            "Invalid message length read from image. "
                            "No message embedded, or wrong steg_key."
                        )

        if length is None:
            raise ValidationError("Image too small to contain a hidden message.")

        needed = 32 + length * 8
        if len(raw_bits) < needed:
            raise ValidationError(
                "Image does not contain enough data for the advertised message length."
            )

        payload_bits = raw_bits[32:needed]
        payload = np.packbits(np.array(payload_bits, dtype=np.uint8)).tobytes()
        return payload
