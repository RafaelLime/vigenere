"""Interface de linha de comando da cifra de Vigenère."""

import argparse
import sys

from .cipher import ALPHABETS, count_letters, decode, effective_key, encode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigenere",
        description="Cifra e decifra textos usando a cifra de Vigenère.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    commands = (
        (
            "encode",
            "Cifra um texto claro, produzindo o criptograma.",
            "Texto claro a cifrar.",
        ),
        (
            "decode",
            "Decifra um criptograma, recuperando o texto claro.",
            "Criptograma a decifrar.",
        ),
    )
    for name, command_help, text_help in commands:
        sub = subparsers.add_parser(name, help=command_help)
        sub.add_argument("text", nargs="?", help=text_help)
        sub.add_argument("-k", "--key", required=True, help="Chave da cifra.")
        sub.add_argument(
            "-a",
            "--alphabet",
            choices=ALPHABETS,
            default="preserve",
            help=(
                "preserve (padrão): mantém maiúsculas/minúsculas, espaços e "
                "pontuação; strict: produz apenas letras A-Z maiúsculas."
            ),
        )
        sub.add_argument("-i", "--input", help="Lê o texto deste arquivo.")
        sub.add_argument("-o", "--output", help="Escreve o resultado neste arquivo.")
        sub.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Exibe um resumo dos parâmetros utilizados (em stderr).",
        )

    return parser


def _warn(message: str) -> None:
    print(f"aviso: {message}", file=sys.stderr)


def _read_text(args: argparse.Namespace) -> str:
    """Obtém o texto de --input, do argumento posicional ou da entrada padrão."""
    if args.input is not None:
        try:
            with open(args.input, encoding="utf-8") as handle:
                return handle.read()
        except OSError as exc:
            raise SystemExit(f"erro: não foi possível ler {args.input!r}: {exc.strerror}")
    if args.text is not None:
        return args.text
    if not sys.stdin.isatty():
        return sys.stdin.read().rstrip("\n")
    raise SystemExit(
        "erro: nenhum texto informado (passe como argumento, com --input ou via stdin)."
    )


def _write_text(result: str, destination: str | None) -> None:
    if destination is None:
        print(result)
        return
    try:
        with open(destination, "w", encoding="utf-8") as handle:
            handle.write(result + "\n")
    except OSError as exc:
        raise SystemExit(f"erro: não foi possível escrever {destination!r}: {exc.strerror}")


def _check_inputs(text: str, key: str, args: argparse.Namespace) -> str:
    """Valida as entradas, avisa sobre casos inesperados e devolve a chave efetiva."""
    key_used = effective_key(key)  # levanta ValueError se a chave não tiver letras

    if key_used != key.lower():
        _warn(
            f"a chave foi reduzida para {key_used!r}; caracteres fora de A-Z foram "
            "ignorados e os acentos foram reduzidos à letra base."
        )
    if len(key_used) == 1:
        _warn("uma chave de uma única letra equivale à cifra de César.")

    letters = count_letters(text)
    if letters == 0:
        _warn("o texto não contém letras de A-Z; nada foi cifrado.")

    if args.verbose:
        print(
            f"comando: {args.command}\n"
            f"alfabeto: {args.alphabet}\n"
            f"chave: {key_used} (tamanho {len(key_used)})\n"
            f"entrada: {len(text)} caracteres, {letters} deles letras",
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
        raise SystemExit(f"erro: {exc}")

    _write_text(result, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
