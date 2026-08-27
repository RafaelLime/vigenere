# Vigenère Cipher

A small Python project that encodes and decodes text using the
[Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher),
exposed through a command-line interface.

## How it works

Each letter of the message is shifted by an amount determined by the
corresponding letter of a repeating key:

- Only letters `A-Z` / `a-z` are transformed; **case is preserved**.
- Any other character (spaces, digits, punctuation) passes through unchanged
  and does **not** consume a key letter.
- Non-letter characters in the key are ignored.

## Installation

```bash
pip install -e .
```

This installs a `vigenere` command. You can also run it without installing via
`python -m vigenere`.

## Usage

The CLI takes a sub-command (`encode` or `decode`), the text, and a `--key`.

```
vigenere encode <plaintext> --key <key>     # -> ciphertext
vigenere decode <ciphertext> --key <key>    # -> plaintext
```

### Examples

Encode plaintext with a key:

```bash
$ vigenere encode "ATTACKATDAWN" --key LEMON
LXFOPVEFRNHR
```

Decode ciphertext with the same key:

```bash
$ vigenere decode "LXFOPVEFRNHR" --key LEMON
ATTACKATDAWN
```

Case and punctuation are preserved:

```bash
$ vigenere encode "Hello, World!" --key secret
Zincs, Pgvnu!
```

Text can also be piped in via stdin:

```bash
$ echo "Attack at dawn" | vigenere encode --key lemon
```

## Running the tests

```bash
pip install pytest
pytest
```
