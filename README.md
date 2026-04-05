# 🔒 Steganography — Professional-Grade Image Steganography

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-green.svg)](tests/)
[![Security: AES-256](https://img.shields.io/badge/security-AES--256--GCM-brightgreen.svg)](SECURITY.md)

A professional-grade Python steganography library that hides secret messages inside lossless images (PNG, BMP, TIFF) using **LSB (Least Significant Bit)** encoding, **AES-256-GCM encryption**, **HMAC-SHA256 integrity verification**, and optional **pixel-order permutation** via a steganographic key.

---

## ✨ Features

| Feature | Details |
|---|---|
| **LSB steganography** | 1 or 2 bits per channel; imperceptible to the naked eye |
| **AES-256-GCM encryption** | Authenticated encryption — confidentiality + integrity |
| **HMAC-SHA256** | Additional integrity layer on the wire format |
| **PBKDF2-HMAC-SHA256** | 600 000 iterations key derivation (NIST 2023 guidance) |
| **Steganographic key** | Key-derived pixel permutation adds obscurity |
| **Random salt & IV** | Fresh cryptographic material for every embed operation |
| **Lossless formats** | PNG, BMP, TIFF — JPEG is intentionally unsupported |
| **Capacity check** | Know if your message fits before embedding |
| **CLI tool** | Full command-line interface with batch support |
| **Comprehensive tests** | pytest suite with integration & unit tests |

---

## 📁 Project Structure

```
steganography/
├── src/
│   ├── __init__.py          # Package exports
│   ├── steganography.py     # Core LSB engine
│   ├── encryption.py        # AES-256-GCM + PBKDF2 + HMAC
│   ├── image_handler.py     # Image I/O and pixel management
│   ├── validation.py        # Input validation helpers
│   └── cli.py               # Command-line interface
├── tests/
│   ├── __init__.py
│   ├── test_steganography.py
│   ├── test_encryption.py
│   ├── test_image_handler.py
│   └── test_validation.py
├── examples/
│   └── example_usage.py     # Runnable demonstration script
├── README.md
├── SECURITY.md
├── requirements.txt
├── setup.py
├── .gitignore
├── LICENSE
└── steg.py                  # Legacy standalone script (kept for reference)
```

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Krishita17/steganography.git
cd steganography

# Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# (Optional) Install as a package so `steg` is on your PATH
pip install -e .
```

### Run the example script

```bash
python examples/example_usage.py
```

---

## 📖 Python API

### Basic embed / extract (no encryption)

```python
from src.steganography import SteganographyEngine

engine = SteganographyEngine()

# Embed a plaintext message
engine.embed(
    input_image="cover.png",
    output_image="stego.png",
    message="Hello, steganography!",
)

# Extract it later
message = engine.extract("stego.png")
print(message)  # Hello, steganography!
```

### Encrypted embed / extract (AES-256-GCM)

```python
engine.embed(
    input_image="cover.png",
    output_image="stego_enc.png",
    message="Top secret payload",
    password="SuperSecretP@ss1",  # Must be ≥ 8 characters
)

message = engine.extract("stego_enc.png", password="SuperSecretP@ss1")
```

### Using a steganographic key (pixel permutation)

```python
# Pixels are visited in a key-derived pseudorandom order
engine.embed(
    input_image="cover.png",
    output_image="stego_perm.png",
    message="Hidden in shuffled pixels",
    steg_key="MyStegKey1234",
)

message = engine.extract("stego_perm.png", steg_key="MyStegKey1234")
```

### Maximum security: encryption + steganographic key

```python
engine.embed(
    input_image="cover.png",
    output_image="stego_max.png",
    message="Maximum security",
    password="StrongPass1!",
    steg_key="StrongStegKey1",
)

message = engine.extract(
    "stego_max.png",
    password="StrongPass1!",
    steg_key="StrongStegKey1",
)
```

### Check image capacity

```python
capacity_bytes = engine.get_capacity("cover.png")
print(f"Can hide up to {capacity_bytes:,} bytes ({capacity_bytes / 1024:.1f} KiB)")
```

### 2-bit mode (double capacity, slight quality trade-off)

```python
engine2 = SteganographyEngine(bits_per_channel=2)
engine2.embed("cover.png", "stego2bpc.png", message="Lots of data", password="P@ss1234")
```

---

## 🖥️ CLI Reference

Install the package first (`pip install -e .`) or prefix commands with `python -m src.cli`.

### Embed a message

```bash
# Plain embed (no encryption)
steg embed -i cover.png -o stego.png -m "Secret message"

# Encrypted embed
steg embed -i cover.png -o stego.png -m "Secret" -p "MyPassword1!"

# Encrypted embed with steganographic key
steg embed -i cover.png -o stego.png -m "Secret" -p "MyPassword1!" -k "StegKey123"

# Embed from a text file
steg embed -i cover.png -o stego.png --message-file secret.txt -p "MyPassword1!"

# 2-bit mode
steg embed --bits 2 -i cover.png -o stego.png -m "More data" -p "MyPassword1!"

# Verbose output
steg -v embed -i cover.png -o stego.png -m "test" -p "MyPassword1!"
```

### Extract a message

```bash
# Print to stdout
steg extract -i stego.png -p "MyPassword1!"

# Save to file
steg extract -i stego.png -p "MyPassword1!" --output-file recovered.txt

# With steganographic key
steg extract -i stego.png -p "MyPassword1!" -k "StegKey123"
```

### Check capacity

```bash
steg capacity -i cover.png
# Output: [OK] Image capacity: 37,464 bytes (36.6 KiB).
```

### Batch processing

Create a JSON config file (`tasks.json`):

```json
[
  {
    "operation": "embed",
    "input": "cover1.png",
    "output": "stego1.png",
    "message": "Message for image 1",
    "password": "Pass1234!"
  },
  {
    "operation": "embed",
    "input": "cover2.png",
    "output": "stego2.png",
    "message_file": "secret.txt",
    "password": "Pass5678!",
    "steg_key": "StegKey1234"
  },
  {
    "operation": "extract",
    "input": "stego1.png",
    "password": "Pass1234!",
    "output_file": "recovered1.txt"
  }
]
```

```bash
steg batch --config tasks.json
```

---

## 🧪 Running Tests

```bash
# Run the full test suite
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run a specific module
pytest tests/test_encryption.py -v
pytest tests/test_steganography.py -v
```

---

## 🔧 Encryption Details

The encryption subsystem in `src/encryption.py` implements the following
wire format for every encrypted blob:

```
┌──────────────┬────────────┬──────────────┬────────────────┬───────────────┐
│  salt (32 B) │  IV (12 B) │  HMAC (32 B) │ length (4 B BE)│  ciphertext   │
└──────────────┴────────────┴──────────────┴────────────────┴───────────────┘
```

| Field | Algorithm | Size |
|-------|-----------|------|
| Salt | OS CSPRNG (`os.urandom`) | 32 bytes |
| IV / Nonce | OS CSPRNG | 12 bytes (GCM) |
| Key derivation | PBKDF2-HMAC-SHA256 (600 000 iters) | 32-byte key |
| Encryption | AES-256-GCM | variable |
| Integrity | HMAC-SHA256 over salt+IV+length+ciphertext | 32 bytes |
| GCM tag | Appended to ciphertext by `cryptography` library | 16 bytes |

The HMAC is computed **after** encryption and verified **before** decryption,
following the *Encrypt-then-MAC* paradigm.

---

## ⚠️ Security Warnings

1. **Use lossless formats only.** JPEG compression destroys LSB data.  
   The library enforces this — only PNG, BMP, and TIFF are accepted.

2. **Never reuse passwords.** Each embed call generates a fresh random salt
   and IV, but password reuse across different messages is still risky.

3. **Steganographic security ≠ cryptographic security.** The steganographic
   key shuffles pixel order but is not a substitute for encryption.
   Always use `--password` for sensitive data.

4. **Cover image matters.** Solid-colour or highly compressible images may
   expose LSB artefacts more easily. Use natural photographs.

5. **Metadata leakage.** File metadata (EXIF, timestamps) is not modified.
   Strip EXIF data with a separate tool if needed.

See [SECURITY.md](SECURITY.md) for the full security guide.

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| [`cryptography`](https://cryptography.io/) | AES-256-GCM, PBKDF2, HMAC |
| [`Pillow`](https://python-pillow.org/) | Image I/O (PNG/BMP/TIFF) |
| [`numpy`](https://numpy.org/) | Pixel manipulation |
| [`pytest`](https://pytest.org/) | Test framework |
| [`pytest-cov`](https://pytest-cov.readthedocs.io/) | Coverage reporting |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your change
4. Ensure all tests pass (`pytest tests/ -v`)
5. Submit a pull request

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.
