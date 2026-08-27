"""Command-line interface for the Vigenère cipher."""

import argparse
import sys

from .cipher import decode, encode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigenere",
        description="Encode or decode text using the Vigenère cipher.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encode_parser = subparsers.add_parser(
        "encode", help="Encode plaintext into ciphertext."
    )
    encode_parser.add_argument("text", nargs="?", help="Plaintext to encode.")
    encode_parser.add_argument("-k", "--key", required=True, help="Cipher key.")

    decode_parser = subparsers.add_parser(
        "decode", help="Decode ciphertext into plaintext."
    )
    decode_parser.add_argument("text", nargs="?", help="Ciphertext to decode.")
    decode_parser.add_argument("-k", "--key", required=True, help="Cipher key.")

    return parser


def _read_text(text: str | None) -> str:
    """Use the positional argument, or fall back to stdin when omitted/piped."""
    if text is not None:
        return text
    if not sys.stdin.isatty():
        return sys.stdin.read().rstrip("\n")
    raise SystemExit("error: no text provided (pass it as an argument or via stdin).")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    text = _read_text(args.text)

    try:
        if args.command == "encode":
            print(encode(text, args.key))
        else:
            print(decode(text, args.key))
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
