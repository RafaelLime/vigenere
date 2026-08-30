# Vigenère Cipher

A small Python project that encodes and decodes text using the
[Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher),
exposed through a command-line interface. The cipher logic is implemented from
scratch in [`vigenere/cipher.py`](vigenere/cipher.py); no cryptography library
is used.

## How it works

The alphabet is the classic 26 letters `A-Z`. Each letter of the message is
shifted by the corresponding letter of the repeating key:

```
encoding:  C_i = (P_i + K_i) mod 26
decoding:  P_i = (C_i - K_i) mod 26
```

`i` counts only the letters of the message, so the key never gets out of sync
with the characters it is applied to.

### How each kind of character is processed

| Input | Treatment |
| --- | --- |
| `a-z` / `A-Z` | Ciphered. Case is preserved in `preserve` mode, forced to uppercase in `strict` mode. |
| Accented letters (`á à â ã ç é ê í ó ô õ ú ü ñ …`) | Folded onto their base letter with Unicode NFD (`é -> e`, `ç -> c`, `ã -> a`, `Ó -> O`) and then ciphered. **The accent is not restored on decoding**: `ação` round-trips as `acao`. |
| Spaces, digits, punctuation | `preserve` mode: copied unchanged, and they do **not** consume a key letter. `strict` mode: discarded. |
| Key characters | Folded the same way; anything that is not a letter is ignored (`l3e!mão` becomes `lemao`). A key with no letters at all is an error. |

### Alphabet modes

- `--alphabet preserve` (default): keeps case, spacing and punctuation, so the
  output stays readable. The layout of the plaintext remains visible in the
  ciphertext.
- `--alphabet strict`: output is a single run of uppercase `A-Z`. This is the
  usual format for cryptanalysis exercises, and it leaks no word boundaries.

```bash
$ vigenere encode "Attack at dawn!" --key lemon
Lxfopv ef rnhr!
$ vigenere encode "Attack at dawn!" --key lemon --alphabet strict
LXFOPVEFRNHR
```

## Installation

```bash
pip install -e .
```

This installs a `vigenere` command. You can also run it without installing via
`python -m vigenere`.

## Usage

```
vigenere encode [text] --key KEY [--alphabet {preserve,strict}] [-i FILE] [-o FILE] [-v]
vigenere decode [text] --key KEY [--alphabet {preserve,strict}] [-i FILE] [-o FILE] [-v]
```

| Option | Meaning |
| --- | --- |
| `-k`, `--key` | The key (required). |
| `-a`, `--alphabet` | `preserve` (default) or `strict`. |
| `-i`, `--input` | Read the text from a file instead of the argument. |
| `-o`, `--output` | Write the result to a file instead of stdout. |
| `-v`, `--verbose` | Print the parameters actually used (on stderr). |

The text can be given as an argument, with `--input`, or piped through stdin.

### Examples

```bash
$ vigenere encode "ATTACKATDAWN" --key LEMON
LXFOPVEFRNHR

$ vigenere decode "LXFOPVEFRNHR" --key LEMON
ATTACKATDAWN

$ vigenere encode "Olá, você está bem?" --key segredo
Gpg, msfs wwzr fha?

$ echo "Attack at dawn" | vigenere encode --key lemon
```

Ciphering a file into the strict A-Z format, with a summary of the parameters:

```bash
$ vigenere encode -i mensagem.txt -o criptograma.txt --key segredo --alphabet strict -v
command: encode
alphabet: strict
key: segredo (length 7)
input: 19 characters, 17 of them letters
```

### Input validation

The program refuses a key with no letters, and warns (on stderr, without
stopping) when:

- the key had characters removed or accents folded, showing the key actually
  used;
- the key is a single letter, which makes it a Caesar cipher;
- the text contains no letter of the alphabet, so nothing was ciphered.

## Running the tests

```bash
pip install -e ".[test]"
pytest
```
