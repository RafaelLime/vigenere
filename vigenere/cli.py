"""Command-line interface for the Vigenère cipher."""

import argparse
import sys

from .cipher import ALPHABETS, count_letters, decode, effective_key, encode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigenere",
        description="Encode or decode text using the Vigenère cipher.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    commands = (
        ("encode", "Encode plaintext into ciphertext.", "Plaintext to encode."),
        ("decode", "Decode ciphertext into plaintext.", "Ciphertext to decode."),
    )
    for name, command_help, text_help in commands:
        sub = subparsers.add_parser(name, help=command_help)
        sub.add_argument("text", nargs="?", help=text_help)
        sub.add_argument("-k", "--key", required=True, help="Cipher key.")
        sub.add_argument(
            "-a",
            "--alphabet",
            choices=ALPHABETS,
            default="preserve",
            help=(
                "preserve (default): keep case, spaces and punctuation; "
                "strict: output only uppercase A-Z."
            ),
        )
        sub.add_argument("-i", "--input", help="Read the text from this file.")
        sub.add_argument("-o", "--output", help="Write the result to this file.")
        sub.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Print a summary of the parameters used (on stderr).",
        )

    return parser


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _read_text(args: argparse.Namespace) -> str:
    """Take the text from --input, the positional argument, or stdin."""
    if args.input is not None:
        try:
            with open(args.input, encoding="utf-8") as handle:
                return handle.read()
        except OSError as exc:
            raise SystemExit(f"error: cannot read {args.input!r}: {exc.strerror}")
    if args.text is not None:
        return args.text
    if not sys.stdin.isatty():
        return sys.stdin.read().rstrip("\n")
    raise SystemExit(
        "error: no text provided (pass it as an argument, with --input, or via stdin)."
    )


def _write_text(result: str, destination: str | None) -> None:
    if destination is None:
        print(result)
        return
    try:
        with open(destination, "w", encoding="utf-8") as handle:
            handle.write(result + "\n")
    except OSError as exc:
        raise SystemExit(f"error: cannot write {destination!r}: {exc.strerror}")


def _check_inputs(text: str, key: str, args: argparse.Namespace) -> str:
    """Validate the inputs, warn about surprising ones, return the effective key."""
    key_used = effective_key(key)  # raises ValueError when the key has no letters

    if key_used != key.lower():
        _warn(
            f"the key was reduced to {key_used!r}; characters outside A-Z were "
            "ignored and accents were folded onto their base letter."
        )
    if len(key_used) == 1:
        _warn("a one-letter key is equivalent to a Caesar cipher.")

    letters = count_letters(text)
    if letters == 0:
        _warn("the text has no A-Z letters, so nothing was ciphered.")

    if args.verbose:
        print(
            f"command: {args.command}\n"
            f"alphabet: {args.alphabet}\n"
            f"key: {key_used} (length {len(key_used)})\n"
            f"input: {len(text)} characters, {letters} of them letters",
            file=sys.stderr,
        )

    return key_used


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    text = _read_text(args)

    try:
        _check_inputs(text, args.key, args)
        transform = encode if args.command == "encode" else decode
        result = transform(text, args.key, alphabet=args.alphabet)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")

    _write_text(result, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
