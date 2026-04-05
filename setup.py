"""
Setup configuration for the steganography package.
"""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    install_requires = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#") and not line.startswith("pytest")
    ]

setup(
    name="steganography",
    version="1.0.0",
    description="Professional-grade LSB image steganography with AES-256 encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Steganography Project",
    license="MIT",
    packages=find_packages(where="."),
    package_dir={"": "."},
    python_requires=">=3.9",
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "steg=src.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Multimedia :: Graphics",
    ],
    keywords="steganography, LSB, AES, encryption, HMAC, image, security",
)
