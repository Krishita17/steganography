"""
Validation Module
=================
Input validation helpers used throughout the steganography package.
"""

import os
import logging
from pathlib import Path
from typing import Optional

import numpy as np

from .image_handler import SUPPORTED_FORMATS

logger = logging.getLogger(__name__)

# Maximum sensible message size (64 MiB)
MAX_MESSAGE_BYTES = 64 * 1024 * 1024

# Minimum password length
MIN_PASSWORD_LENGTH = 8


class ValidationError(Exception):
    """Raised when a validation check fails."""


class Validator:
    """
    Centralised validation logic for the steganography package.

    All public methods either return ``True`` on success or raise
    :class:`ValidationError` with a descriptive message.
    """

    # ------------------------------------------------------------------ #
    #  Path / file checks
    # ------------------------------------------------------------------ #

    def validate_input_path(self, path: str) -> bool:
        """
        Ensure *path* exists and is a readable file.

        Raises
        ------
        ValidationError
        """
        if not path or not isinstance(path, str):
            raise ValidationError("Path must be a non-empty string.")
        p = Path(path)
        if not p.exists():
            raise ValidationError(f"File not found: {path}")
        if not p.is_file():
            raise ValidationError(f"Path is not a file: {path}")
        if not os.access(path, os.R_OK):
            raise ValidationError(f"File is not readable: {path}")
        logger.debug("Input path validated: %s", path)
        return True

    def validate_output_path(self, path: str) -> bool:
        """
        Ensure *path* can be written (parent directory exists).

        Raises
        ------
        ValidationError
        """
        if not path or not isinstance(path, str):
            raise ValidationError("Output path must be a non-empty string.")
        p = Path(path)
        if not p.parent.exists():
            raise ValidationError(
                f"Output directory does not exist: {p.parent}"
            )
        logger.debug("Output path validated: %s", path)
        return True

    def validate_image_format(self, path: str) -> bool:
        """
        Ensure the file extension belongs to a supported lossless format.

        Raises
        ------
        ValidationError
        """
        suffix = Path(path).suffix.lower()
        if suffix not in SUPPORTED_FORMATS:
            raise ValidationError(
                f"Unsupported image format '{suffix}'. "
                f"Supported lossless formats: {sorted(SUPPORTED_FORMATS)}"
            )
        return True

    # ------------------------------------------------------------------ #
    #  Message checks
    # ------------------------------------------------------------------ #

    def validate_message(self, message: str) -> bool:
        """
        Ensure *message* is a non-empty string within the allowed size.

        Raises
        ------
        ValidationError
        """
        if not isinstance(message, str):
            raise ValidationError("Message must be a string.")
        if not message:
            raise ValidationError("Message must not be empty.")
        if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValidationError(
                f"Message exceeds maximum size of {MAX_MESSAGE_BYTES} bytes."
            )
        return True

    def validate_capacity(
        self,
        message_bytes: int,
        image_array: np.ndarray,
        bits_per_channel: int = 1,
    ) -> bool:
        """
        Check that the image has enough capacity for *message_bytes* plus
        the 4-byte length header.

        Raises
        ------
        ValidationError
        """
        total_bits = image_array.size * bits_per_channel
        # 4 bytes = 32 bits reserved for the length header
        available_bytes = (total_bits - 32) // 8
        required_bytes = message_bytes + 4   # payload + header

        if message_bytes > available_bytes:
            raise ValidationError(
                f"Message too large: {message_bytes} bytes needed but image "
                f"can only hold {available_bytes} bytes "
                f"({image_array.shape[0]}×{image_array.shape[1]} image)."
            )
        logger.debug(
            "Capacity OK: %d bytes available, %d bytes needed.",
            available_bytes,
            message_bytes,
        )
        return True

    # ------------------------------------------------------------------ #
    #  Password checks
    # ------------------------------------------------------------------ #

    def validate_password(self, password: str, *, field: str = "password") -> bool:
        """
        Ensure *password* meets minimum length requirements.

        Parameters
        ----------
        password : str
        field    : str   Label used in error messages (e.g. ``"steg_key"``).

        Raises
        ------
        ValidationError
        """
        if not isinstance(password, str):
            raise ValidationError(f"{field} must be a string.")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValidationError(
                f"{field} must be at least {MIN_PASSWORD_LENGTH} characters long."
            )
        return True

    def validate_optional_password(
        self, password: Optional[str], *, field: str = "password"
    ) -> bool:
        """
        Like :meth:`validate_password` but allows ``None`` / empty string
        (meaning "no password supplied").
        """
        if password is None or password == "":
            return True
        return self.validate_password(password, field=field)
