"""Core Vigenère cipher logic.

The Vigenère cipher shifts each alphabetic character of the message by an
amount determined by the corresponding character of a repeating key. Only
letters A-Z / a-z are transformed; case is preserved and any other character
(spaces, digits, punctuation) is passed through unchanged. Non-letter
characters do not consume a key character.
"""

ALPHABET_SIZE = 26


def _clean_key(key: str) -> list[int]:
    """Return the key as a list of 0-25 shift offsets, ignoring non-letters."""
    offsets = [ord(c.lower()) - ord("a") for c in key if c.isalpha()]
    if not offsets:
        raise ValueError("Key must contain at least one alphabetic character.")
    return offsets


def _transform(text: str, key: str, sign: int) -> str:
    """Shift the letters of ``text`` by the key. ``sign`` is +1 to encode, -1 to decode."""
    offsets = _clean_key(key)
    result = []
    key_index = 0

    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = offsets[key_index % len(offsets)] * sign
            result.append(chr((ord(char) - base + shift) % ALPHABET_SIZE + base))
            key_index += 1
        else:
            result.append(char)

    return "".join(result)


def encode(plaintext: str, key: str) -> str:
    """Encode ``plaintext`` with ``key`` and return the ciphertext."""
    return _transform(plaintext, key, sign=1)


def decode(ciphertext: str, key: str) -> str:
    """Decode ``ciphertext`` with ``key`` and return the plaintext."""
    return _transform(ciphertext, key, sign=-1)
