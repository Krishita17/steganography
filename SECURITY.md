# Security Guide

This document describes the security design, assumptions, and best practices
for the steganography package.

---

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Passive observer reads the stego image | AES-256-GCM encryption makes the payload unreadable without the password |
| Active attacker tampers with the stego image | HMAC-SHA256 + GCM authentication tag detects any modification |
| Brute-force password attack | PBKDF2-HMAC-SHA256 with 600 000 iterations slows guessing to ~1–10 attempts/second on commodity hardware |
| Known-cover attack (attacker has both cover and stego) | Without the steganographic key, the pixel order is opaque; without the encryption password, the payload is ciphertext |
| Wrong-password leaks timing information | HMAC is verified with `hmac.compare_digest` (constant-time) |

---

## Algorithms

### Key Derivation — PBKDF2-HMAC-SHA256

```
key = PBKDF2-HMAC-SHA256(
    password  = user_password,
    salt      = os.urandom(32),   # 256-bit random salt
    iterations = 600_000,          # NIST SP 800-132 (2023) recommendation
    dklen     = 32,               # 256-bit key
)
```

A fresh 32-byte salt is generated for **every** embed operation, so two
invocations with the same password produce different keys.

### Encryption — AES-256-GCM

- **Key size:** 256 bits  
- **Nonce/IV:** 96-bit random (generated with `os.urandom(12)` — recommended
  for GCM per NIST SP 800-38D)  
- **Authentication tag:** 128 bits (appended to ciphertext by the
  `cryptography` library)  
- The GCM tag authenticates both the ciphertext and, implicitly, the associated
  data (AAD — none is used here; integrity is handled by HMAC instead)

### Message Integrity — HMAC-SHA256 (Encrypt-then-MAC)

```
mac_data = salt ‖ iv ‖ length_bytes ‖ ciphertext
hmac = HMAC-SHA256(key, mac_data)
```

The HMAC is computed **after** AES-GCM encryption (Encrypt-then-MAC pattern).
On decryption, the HMAC is verified **before** any decryption attempt, preventing
chosen-ciphertext oracle attacks.

### Steganographic Key — PBKDF2-HMAC-SHA256

A separate 32-byte seed is derived from the `steg_key`:

```
seed = PBKDF2-HMAC-SHA256(
    password   = steg_key,
    salt       = b"steg_key_salt_v1",   # fixed per-project salt
    iterations = 100_000,
    dklen      = 32,
)
```

The first 4 bytes of the seed initialise a NumPy `default_rng` which
shuffles the pixel index array.  The same `steg_key` always produces the
same permutation for a given image size.

> **Note:** The steganographic key adds *obscurity* (security-through-obscurity)
> but does **not** replace cryptographic security.  Always use `password` for
> sensitive data.

---

## Wire Format

```
┌──────────────┬────────────┬──────────────┬────────────────┬───────────────┐
│  salt (32 B) │  IV (12 B) │  HMAC (32 B) │ length (4 B BE)│  ciphertext   │
└──────────────┴────────────┴──────────────┴────────────────┴───────────────┘
Total header: 80 bytes
```

The **length** field (big-endian `uint32`) encodes the number of **ciphertext**
bytes (including the 16-byte GCM authentication tag).

---

## Best Practices

### Passwords

- Use a **password manager** to generate long random passwords (≥ 16 characters).
- **Never share** the password over the same channel as the stego image.
- The library enforces a minimum of **8 characters** but we recommend at least
  16 for security.

### Cover Images

- Use **natural photographs** — they have high entropy in the LSBs, making
  the stego harder to detect statistically.
- Avoid solid-colour images or synthetic graphics — statistical analysis
  (e.g., chi-square test) can detect LSB embedding more easily.
- The stego image must be shared as a **lossless** file (PNG, BMP, TIFF).
  Converting to JPEG will destroy the hidden data.

### Operational Security

1. **Delete cover originals** from shared storage before distributing the
   stego image if you don't want the original available for comparison.
2. **Strip EXIF metadata** — tools like `exiftool -all= stego.png` remove
   GPS coordinates, camera model, timestamps, etc.
3. **Use a trusted channel** to exchange the password (e.g., Signal, in-person).
4. Do **not** reuse passwords across different hidden messages.
5. If using `steg_key`, communicate it separately from the encryption password.

### What This Library Does NOT Protect Against

- **Steganalysis** by a sophisticated adversary with access to many stego
  images from the same tool (statistical fingerprinting of the LSB pattern).
- **Side-channel attacks** on the host system (memory dumps, swap files).
- **Passphrase interception** — use a secure channel for key exchange.
- **Metadata leakage** — strip EXIF/XMP data separately.

---

## Dependency Security

| Package | Notes |
|---------|-------|
| `cryptography` | Wraps OpenSSL; keep updated for security patches |
| `Pillow` | Image parsing; historically has had CVEs — keep updated |
| `numpy` | Numerical library; low-risk for crypto operations |

Run `pip list --outdated` regularly and update dependencies.

---

## Reporting Vulnerabilities

If you discover a security vulnerability in this project, please open a
**private** issue or contact the maintainer directly.  Do not disclose
vulnerabilities publicly until a fix is available.

---

## References

- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) — Password-Based Key Derivation
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — Recommendation for GCM
- [RFC 2104](https://tools.ietf.org/html/rfc2104) — HMAC
- [Python `cryptography` library](https://cryptography.io/en/latest/)
- [Least Significant Bit steganography](https://en.wikipedia.org/wiki/Steganography#Digital)
