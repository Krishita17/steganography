"""
CLI Module
==========
Command-line interface for the steganography package.

Usage examples::

    # Embed a message (with encryption)
    python -m src.cli embed -i cover.png -o stego.png -m "Secret" -p "myPass123"

    # Extract a message
    python -m src.cli extract -i stego.png -p "myPass123"

    # Check image capacity
    python -m src.cli capacity -i cover.png

    # Batch embed from a config file
    python -m src.cli batch --config batch.json
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from .steganography import SteganographyEngine
from .validation import ValidationError

# --------------------------------------------------------------------------- #
#  Logging setup
# --------------------------------------------------------------------------- #

def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# --------------------------------------------------------------------------- #
#  Sub-command handlers
# --------------------------------------------------------------------------- #

def cmd_embed(args: argparse.Namespace, engine: SteganographyEngine) -> int:
    """Handle the ``embed`` sub-command."""
    password: Optional[str] = args.password or None
    steg_key: Optional[str] = args.steg_key or None

    # Read message from --message flag or --message-file
    if args.message:
        message = args.message
    elif args.message_file:
        p = Path(args.message_file)
        if not p.exists():
            print(f"[ERROR] Message file not found: {args.message_file}", file=sys.stderr)
            return 1
        message = p.read_text(encoding="utf-8")
    else:
        print("[ERROR] Provide --message or --message-file.", file=sys.stderr)
        return 1

    try:
        bytes_written = engine.embed(
            input_image=args.input,
            output_image=args.output,
            message=message,
            password=password,
            steg_key=steg_key,
        )
        print(f"[OK] Embedded {bytes_written} bytes into '{args.output}'.")
        return 0
    except (ValidationError, FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


def cmd_extract(args: argparse.Namespace, engine: SteganographyEngine) -> int:
    """Handle the ``extract`` sub-command."""
    password: Optional[str] = args.password or None
    steg_key: Optional[str] = args.steg_key or None

    try:
        message = engine.extract(
            input_image=args.input,
            password=password,
            steg_key=steg_key,
        )
        if args.output_file:
            Path(args.output_file).write_text(message, encoding="utf-8")
            print(f"[OK] Extracted message written to '{args.output_file}'.")
        else:
            print("[OK] Extracted message:")
            print(message)
        return 0
    except (ValidationError, FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


def cmd_capacity(args: argparse.Namespace, engine: SteganographyEngine) -> int:
    """Handle the ``capacity`` sub-command."""
    try:
        cap = engine.get_capacity(args.input)
        print(f"[OK] Image capacity: {cap} bytes ({cap / 1024:.1f} KiB).")
        return 0
    except (ValidationError, FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


def cmd_batch(args: argparse.Namespace, engine: SteganographyEngine) -> int:
    """
    Handle the ``batch`` sub-command.

    The JSON config file must be a list of objects with keys::

        {
            "operation": "embed" | "extract",
            "input":  "...",
            "output": "...",           (embed only)
            "message": "...",          (embed only; or use message_file)
            "message_file": "...",     (embed only; alternative to message)
            "output_file": "...",      (extract only; optional)
            "password": "...",         (optional)
            "steg_key": "..."          (optional)
        }
    """
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[ERROR] Config file not found: {args.config}", file=sys.stderr)
        return 1

    with config_path.open(encoding="utf-8") as f:
        tasks = json.load(f)

    if not isinstance(tasks, list):
        print("[ERROR] Config file must contain a JSON array of task objects.", file=sys.stderr)
        return 1

    errors = 0
    for idx, task in enumerate(tasks):
        op = task.get("operation", "").lower()
        print(f"\n--- Task {idx + 1}: {op} ---")

        # Build a namespace to reuse the existing handlers
        ns = argparse.Namespace(
            input=task.get("input"),
            output=task.get("output"),
            message=task.get("message"),
            message_file=task.get("message_file"),
            password=task.get("password"),
            steg_key=task.get("steg_key"),
            output_file=task.get("output_file"),
        )

        if op == "embed":
            rc = cmd_embed(ns, engine)
        elif op == "extract":
            rc = cmd_extract(ns, engine)
        else:
            print(f"[ERROR] Unknown operation '{op}'.", file=sys.stderr)
            rc = 1

        if rc != 0:
            errors += 1

    if errors:
        print(f"\n[DONE] Batch completed with {errors} error(s).")
    else:
        print("\n[DONE] All batch tasks completed successfully.")
    return 0 if errors == 0 else 1


# --------------------------------------------------------------------------- #
#  Argument parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="steg",
        description="Professional-grade LSB image steganography with AES-256 encryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Embed with encryption:
    python -m src.cli embed -i cover.png -o stego.png -m "Secret" -p "Pass1234"

  Embed with encryption + steganographic key:
    python -m src.cli embed -i cover.png -o stego.png -m "Secret" -p "Pass1234" -k "StegKey1"

  Extract:
    python -m src.cli extract -i stego.png -p "Pass1234"

  Extract to file:
    python -m src.cli extract -i stego.png -p "Pass1234" --output-file msg.txt

  Check capacity:
    python -m src.cli capacity -i cover.png

  Batch processing:
    python -m src.cli batch --config tasks.json
        """,
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging."
    )
    parser.add_argument(
        "--bits", type=int, default=1, choices=[1, 2],
        help="LSBs per channel (default: 1).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ---- embed --------------------------------------------------------
    p_embed = sub.add_parser("embed", help="Embed a message in an image.")
    p_embed.add_argument("-i", "--input", required=True, help="Cover image path.")
    p_embed.add_argument("-o", "--output", required=True, help="Output stego image path.")
    msg_group = p_embed.add_mutually_exclusive_group(required=True)
    msg_group.add_argument("-m", "--message", help="Message text to embed.")
    msg_group.add_argument("--message-file", dest="message_file", help="File containing message.")
    p_embed.add_argument("-p", "--password", default="", help="Encryption password (AES-256).")
    p_embed.add_argument("-k", "--steg-key", dest="steg_key", default="", help="Steganographic key.")

    # ---- extract ------------------------------------------------------
    p_extract = sub.add_parser("extract", help="Extract a hidden message from an image.")
    p_extract.add_argument("-i", "--input", required=True, help="Stego image path.")
    p_extract.add_argument("-p", "--password", default="", help="Decryption password.")
    p_extract.add_argument("-k", "--steg-key", dest="steg_key", default="", help="Steganographic key.")
    p_extract.add_argument("--output-file", dest="output_file", default="", help="Write message to file.")

    # ---- capacity -----------------------------------------------------
    p_cap = sub.add_parser("capacity", help="Show image embedding capacity.")
    p_cap.add_argument("-i", "--input", required=True, help="Image path.")

    # ---- batch --------------------------------------------------------
    p_batch = sub.add_parser("batch", help="Process multiple tasks from a JSON config.")
    p_batch.add_argument("--config", required=True, help="Path to JSON config file.")

    return parser


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose if hasattr(args, "verbose") else False)

    engine = SteganographyEngine(bits_per_channel=args.bits if hasattr(args, "bits") else 1)

    dispatch = {
        "embed": cmd_embed,
        "extract": cmd_extract,
        "capacity": cmd_capacity,
        "batch": cmd_batch,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args, engine)


if __name__ == "__main__":
    sys.exit(main())
