"""
Example Usage of the Steganography Package
===========================================
This script demonstrates the core capabilities of the steganography library:
1. Basic embed/extract without encryption
2. Encrypted embed/extract with AES-256-GCM
3. Using a steganographic key for pixel permutation
4. Combining encryption + steganographic key
5. Capacity checking

Run from the project root:
    python examples/example_usage.py
"""

import os
import sys
import tempfile
import numpy as np
from PIL import Image

# Ensure the project root is on the path when run directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.steganography import SteganographyEngine
from src.encryption import EncryptionManager
from src.image_handler import ImageHandler
from src.validation import Validator, ValidationError


def create_sample_image(path: str, width: int = 300, height: int = 300) -> None:
    """Create a sample RGB PNG image for demonstration."""
    arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path)
    print(f"  Created sample image: {path} ({width}x{height} px)")


def separator(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main():
    engine = SteganographyEngine()

    with tempfile.TemporaryDirectory() as tmpdir:

        cover = os.path.join(tmpdir, "cover.png")
        create_sample_image(cover)

        # ------------------------------------------------------------------ #
        # 1. Basic embed/extract (no encryption)
        # ------------------------------------------------------------------ #
        separator("1. Basic Embed / Extract (no encryption)")
        stego1 = os.path.join(tmpdir, "stego_basic.png")
        message = "Hello from the steganography package! 🌍"
        engine.embed(cover, stego1, message)
        print(f"  Embedded: {repr(message)}")
        extracted = engine.extract(stego1)
        print(f"  Extracted: {repr(extracted)}")
        assert extracted == message, "Mismatch!"
        print("  ✓ Basic roundtrip successful")

        # ------------------------------------------------------------------ #
        # 2. Encrypted embed/extract
        # ------------------------------------------------------------------ #
        separator("2. Encrypted Embed / Extract (AES-256-GCM)")
        stego2 = os.path.join(tmpdir, "stego_encrypted.png")
        password = "SuperSecretP@ss1"
        secret_msg = "TOP SECRET: Launch codes are 4-8-15-16-23-42"
        engine.embed(cover, stego2, secret_msg, password=password)
        print(f"  Embedded (encrypted): {repr(secret_msg[:30])}...")
        decrypted = engine.extract(stego2, password=password)
        print(f"  Extracted: {repr(decrypted[:30])}...")
        assert decrypted == secret_msg
        print("  ✓ Encrypted roundtrip successful")

        # Wrong password should fail
        try:
            engine.extract(stego2, password="WrongPassword1!")
            print("  ✗ Wrong password should have raised an error!")
        except ValidationError as e:
            print(f"  ✓ Wrong password correctly rejected: {e}")

        # ------------------------------------------------------------------ #
        # 3. Steganographic key (pixel permutation)
        # ------------------------------------------------------------------ #
        separator("3. Steganographic Key (pixel permutation)")
        stego3 = os.path.join(tmpdir, "stego_stegkey.png")
        steg_key = "MyStegKey1234"
        engine.embed(cover, stego3, "Hidden with permuted pixels", steg_key=steg_key)
        msg3 = engine.extract(stego3, steg_key=steg_key)
        print(f"  Extracted: {repr(msg3)}")
        assert msg3 == "Hidden with permuted pixels"
        print("  ✓ Steganographic key roundtrip successful")

        # ------------------------------------------------------------------ #
        # 4. Combined: encryption + steganographic key
        # ------------------------------------------------------------------ #
        separator("4. Encryption + Steganographic Key (maximum security)")
        stego4 = os.path.join(tmpdir, "stego_combined.png")
        engine.embed(
            cover, stego4,
            "Maximum security message",
            password="CombinedPass1!",
            steg_key="CombinedStegKey1",
        )
        msg4 = engine.extract(
            stego4,
            password="CombinedPass1!",
            steg_key="CombinedStegKey1",
        )
        assert msg4 == "Maximum security message"
        print("  ✓ Combined security roundtrip successful")

        # ------------------------------------------------------------------ #
        # 5. Capacity check
        # ------------------------------------------------------------------ #
        separator("5. Capacity Check")
        cap = engine.get_capacity(cover)
        print(f"  Cover image capacity: {cap:,} bytes ({cap/1024:.1f} KiB)")
        img_h = ImageHandler()
        arr, _ = img_h.load_image(cover)
        print(f"  Image dimensions: {arr.shape[1]}×{arr.shape[0]} px, "
              f"{arr.shape[2]} channels")

        # ------------------------------------------------------------------ #
        # 6. Direct EncryptionManager usage
        # ------------------------------------------------------------------ #
        separator("6. Direct EncryptionManager usage")
        em = EncryptionManager()
        plaintext = b"Raw bytes to encrypt"
        blob = em.encrypt(plaintext, "DirectPass1!")
        recovered = em.decrypt(blob, "DirectPass1!")
        assert recovered == plaintext
        print(f"  Encrypted {len(plaintext)} bytes → {len(blob)} bytes (overhead: "
              f"{len(blob)-len(plaintext)} bytes for salt/IV/HMAC/GCM-tag)")
        print("  ✓ EncryptionManager direct usage OK")

        # ------------------------------------------------------------------ #
        # 7. Validation examples
        # ------------------------------------------------------------------ #
        separator("7. Validation Examples")
        val = Validator()

        # Valid inputs pass silently
        val.validate_message("A valid message")
        val.validate_password("ValidPass1!")
        print("  ✓ Valid inputs pass validation")

        # Invalid inputs raise descriptive errors
        for bad_call, label in [
            (lambda: val.validate_message(""), "empty message"),
            (lambda: val.validate_password("short"), "short password"),
            (lambda: val.validate_image_format("image.jpg"), "JPEG format"),
        ]:
            try:
                bad_call()
                print(f"  ✗ Should have failed for {label}")
            except ValidationError as e:
                print(f"  ✓ Correctly rejected {label}: {e}")

    print("\n" + "="*60)
    print("  All examples completed successfully! ✓")
    print("="*60)


if __name__ == "__main__":
    main()
