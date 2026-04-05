"""
Encryption Module
=================
Provides AES-256-GCM encryption, HMAC-SHA256 integrity verification,
and PBKDF2-based key derivation for securing hidden messages.
"""

import os
import hmac
import hashlib
import logging
import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #
SALT_SIZE = 32          # bytes – for PBKDF2
IV_SIZE = 12            # bytes – GCM nonce (recommended 96-bit)
HMAC_SIZE = 32          # bytes – SHA-256 output
KEY_SIZE = 32           # bytes – AES-256
PBKDF2_ITERATIONS = 600_000   # NIST recommended minimum (2023)
PBKDF2_HASH = hashes.SHA256()

# Wire format written before the ciphertext:
#   salt (32) | iv (12) | hmac (32) | len (4, big-endian uint32)
HEADER_SIZE = SALT_SIZE + IV_SIZE + HMAC_SIZE + 4


class EncryptionManager:
    """
    Handles AES-256-GCM encryption/decryption with PBKDF2 key derivation
    and HMAC-SHA256 integrity checks.

    Example
    -------
    >>> em = EncryptionManager()
    >>> ct = em.encrypt(b"secret message", "passphrase")
    >>> pt = em.decrypt(ct, "passphrase")
    >>> assert pt == b"secret message"
    """

    # ------------------------------------------------------------------ #
    #  Key derivation
    # ------------------------------------------------------------------ #

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit key from *password* using PBKDF2-HMAC-SHA256.

        Parameters
        ----------
        password : str
            User-supplied passphrase.
        salt : bytes
            Cryptographically random 32-byte salt.

        Returns
        -------
        bytes
            32-byte derived key.
        """
        if not isinstance(password, str) or not password:
            raise ValueError("Password must be a non-empty string.")
        if not isinstance(salt, bytes) or len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes.")

        kdf = PBKDF2HMAC(
            algorithm=PBKDF2_HASH,
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))
        logger.debug("Key derived successfully (iterations=%d).", PBKDF2_ITERATIONS)
        return key

    # ------------------------------------------------------------------ #
    #  HMAC helpers
    # ------------------------------------------------------------------ #

    def compute_hmac(self, key: bytes, data: bytes) -> bytes:
        """Return a 32-byte HMAC-SHA256 of *data* under *key*."""
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify_hmac(self, key: bytes, data: bytes, tag: bytes) -> bool:
        """
        Constant-time HMAC verification.

        Returns
        -------
        bool
            ``True`` if the tag is valid.
        """
        expected = self.compute_hmac(key, data)
        return hmac.compare_digest(expected, tag)

    # ------------------------------------------------------------------ #
    #  Encrypt / Decrypt
    # ------------------------------------------------------------------ #

    def encrypt(self, plaintext: bytes, password: str) -> bytes:
        """
        Encrypt *plaintext* with AES-256-GCM.

        The returned blob contains::

            salt (32) | iv (12) | hmac (32) | length (4) | ciphertext

        The HMAC covers ``salt || iv || length || ciphertext`` and is
        computed **after** encryption so that the decrypt side can
        authenticate the envelope before attempting decryption.

        Parameters
        ----------
        plaintext : bytes
        password  : str

        Returns
        -------
        bytes
            Encrypted blob ready for embedding.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes.")

        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)
        key = self.derive_key(password, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)   # GCM tag appended

        length_bytes = struct.pack(">I", len(ciphertext))
        mac_data = salt + iv + length_bytes + ciphertext
        mac = self.compute_hmac(key, mac_data)

        blob = salt + iv + mac + length_bytes + ciphertext
        logger.debug(
            "Encrypted %d bytes → %d bytes (overhead=%d).",
            len(plaintext), len(blob), len(blob) - len(plaintext),
        )
        return blob

    def decrypt(self, blob: bytes, password: str) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        blob     : bytes
            Encrypted blob as returned by :meth:`encrypt`.
        password : str

        Returns
        -------
        bytes
            Original plaintext.

        Raises
        ------
        ValueError
            If the HMAC check fails or the GCM tag is invalid (tampered data).
        """
        if not isinstance(blob, bytes):
            raise TypeError("blob must be bytes.")
        if len(blob) < HEADER_SIZE:
            raise ValueError(
                f"Blob too short: expected at least {HEADER_SIZE} bytes, "
                f"got {len(blob)}."
            )

        salt = blob[:SALT_SIZE]
        iv = blob[SALT_SIZE: SALT_SIZE + IV_SIZE]
        stored_mac = blob[SALT_SIZE + IV_SIZE: SALT_SIZE + IV_SIZE + HMAC_SIZE]
        length_bytes = blob[
            SALT_SIZE + IV_SIZE + HMAC_SIZE:
            SALT_SIZE + IV_SIZE + HMAC_SIZE + 4
        ]
        ciphertext = blob[HEADER_SIZE:]

        key = self.derive_key(password, salt)

        expected_len = struct.unpack(">I", length_bytes)[0]
        if len(ciphertext) != expected_len:
            raise ValueError("Ciphertext length mismatch — data may be corrupted.")

        mac_data = salt + iv + length_bytes + ciphertext
        if not self.verify_hmac(key, mac_data, stored_mac):
            raise ValueError(
                "HMAC verification failed — wrong password or data tampered."
            )

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError(
                "AES-GCM authentication tag invalid — data corrupted or tampered."
            ) from exc

        logger.debug("Decrypted %d bytes successfully.", len(plaintext))
        return plaintext

    # ------------------------------------------------------------------ #
    #  Convenience: steganographic key mixing
    # ------------------------------------------------------------------ #

    @staticmethod
    def derive_steg_key(steg_password: str, salt: bytes) -> bytes:
        """
        Derive a deterministic byte-sequence from *steg_password* that can
        be used to permute the pixel traversal order (steganographic key).

        Returns 32 bytes suitable for use as a seed.
        """
        return hashlib.pbkdf2_hmac(
            "sha256",
            steg_password.encode("utf-8"),
            salt,
            iterations=100_000,
            dklen=32,
        )
