"""Core Vigenère cipher logic.

The cipher works over the classic 26-letter alphabet ``A-Z``. Every input
character is first *folded* onto that alphabet:

- ASCII letters ``a-z`` / ``A-Z`` are used as they are;
- accented letters are decomposed (Unicode NFD) and reduced to their base
  letter, so ``é -> e``, ``ç -> c``, ``ã -> a``, ``Ó -> O``. Note that the
  accent is therefore **lost**: decoding gives back ``acao``, not ``ação``;
- anything else (spaces, digits, punctuation) is not part of the alphabet.

How the non-alphabet characters are handled depends on the ``alphabet`` mode:

``preserve`` (default)
    They are copied to the output unchanged and do **not** consume a key
    letter. Letter case is preserved. Convenient for reading the result, but
    the punctuation/spacing of the plaintext stays visible in the ciphertext.

``strict``
    They are discarded. The output is a continuous run of uppercase ``A-Z``,
    the usual format for classical cryptanalysis exercises.

The mathematical core is in :func:`_transform`:
    encoding:  C_i = (P_i + K_i) mod 26
    decoding:  P_i = (C_i - K_i) mod 26
where ``i`` counts only the letters of the message and ``K`` repeats cyclically.
"""

import unicodedata

ALPHABET_SIZE = 26
ALPHABETS = ("preserve", "strict")


def fold(char: str) -> str | None:
    """Fold ``char`` onto the A-Z alphabet.

    Returns the base ASCII letter, keeping the original case, or ``None`` when
    the character is not a letter of the alphabet. Accented letters are
    normalised with NFD, which splits e.g. ``ç`` into ``c`` + combining
    cedilla, so the first code point is the base letter.
    """
    base = unicodedata.normalize("NFD", char)[:1]
    if "a" <= base <= "z" or "A" <= base <= "Z":
        return base
    return None


def key_offsets(key: str) -> list[int]:
    """Return the key as a list of 0-25 shifts, ignoring non-alphabet characters."""
    offsets = [
        ord(letter.lower()) - ord("a")
        for letter in (fold(char) for char in key)
        if letter is not None
    ]
    if not offsets:
        raise ValueError("Key must contain at least one letter (A-Z).")
    return offsets


def effective_key(key: str) -> str:
    """Return the key that is actually used: folded to A-Z, lowercase, letters only."""
    return "".join(chr(offset + ord("a")) for offset in key_offsets(key))


def count_letters(text: str) -> int:
    """Number of characters of ``text`` that belong to the A-Z alphabet."""
    return sum(1 for char in text if fold(char) is not None)


def _transform(text: str, key: str, sign: int, alphabet: str) -> str:
    """Shift the letters of ``text`` by the key. ``sign`` is +1 to encode, -1 to decode."""
    if alphabet not in ALPHABETS:
        raise ValueError(
            f"Unknown alphabet mode {alphabet!r}; expected one of {', '.join(ALPHABETS)}."
        )

    offsets = key_offsets(key)
    result = []
    key_index = 0  # advances only on letters, so the key stays in sync

    for char in text:
        letter = fold(char)

        if letter is None:
            # Not part of the alphabet: kept verbatim (and the key does not
            # advance) in "preserve" mode, dropped in "strict" mode.
            if alphabet == "preserve":
                result.append(char)
            continue

        # C_i = (P_i + K_i) mod 26   /   P_i = (C_i - K_i) mod 26
        base = ord("A") if letter.isupper() else ord("a")
        shift = offsets[key_index % len(offsets)] * sign
        shifted = chr((ord(letter) - base + shift) % ALPHABET_SIZE + base)

        result.append(shifted.upper() if alphabet == "strict" else shifted)
        key_index += 1

    return "".join(result)


def encode(plaintext: str, key: str, alphabet: str = "preserve") -> str:
    """Encode ``plaintext`` with ``key`` and return the ciphertext."""
    return _transform(plaintext, key, sign=1, alphabet=alphabet)


def decode(ciphertext: str, key: str, alphabet: str = "preserve") -> str:
    """Decode ``ciphertext`` with ``key`` and return the plaintext."""
    return _transform(ciphertext, key, sign=-1, alphabet=alphabet)
