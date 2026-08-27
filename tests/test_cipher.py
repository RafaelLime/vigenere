"""Tests for the Vigenère cipher core logic."""

import pytest

from vigenere.cipher import decode, encode


def test_encode_classic_example():
    # The canonical Vigenère example: ATTACKATDAWN / LEMON -> LXFOPVEFRNHR
    assert encode("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"


def test_decode_classic_example():
    assert decode("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"


def test_roundtrip():
    message = "Hello, World!"
    key = "secret"
    assert decode(encode(message, key), key) == message


def test_preserves_case():
    assert encode("Hello", "key") == encode("Hello", "key")
    result = encode("aA", "b")
    assert result[0].islower() and result[1].isupper()


def test_non_letters_pass_through_and_do_not_consume_key():
    # Spaces/punctuation are untouched and don't advance the key.
    assert encode("ab cd", "aa") == "ab cd"  # key of all 'a' == no shift
    assert encode("a!b", "bc") == "b!d"


def test_key_ignores_non_alpha_characters():
    assert encode("attack", "l3e!m") == encode("attack", "lem")


def test_empty_key_raises():
    with pytest.raises(ValueError):
        encode("hello", "123")
