"""Tests for the Vigenère cipher core logic."""

import pytest

from vigenere.cipher import count_letters, decode, effective_key, encode, fold


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
    assert encode("Hello", "key") == "Rijvs"
    assert encode("hELLO", "key") == "rIJVS"


def test_accented_letters_are_folded_onto_the_base_letter():
    # "ação" is ciphered as if it were "acao"; the accents are lost.
    assert encode("ação", "chave") == encode("acao", "chave") == "cjaj"
    assert decode("cjaj", "chave") == "acao"


def test_accent_folding_keeps_case():
    assert fold("Ç") == "C"
    assert fold("é") == "e"
    assert fold("5") is None
    assert encode("Ção", "aaa") == "Cao"


def test_accented_letters_stay_in_sync_with_the_key():
    # Every letter consumes exactly one key letter, accented or not.
    assert encode("aéa", "bcd") == encode("aea", "bcd")
    assert encode("aèa", "bcd") == encode("aea", "bcd")
    assert encode("añn", "bcd") == encode("ann", "bcd")


def test_non_letters_pass_through_and_do_not_consume_key():
    # Spaces/punctuation are untouched and don't advance the key.
    assert encode("ab cd", "aa") == "ab cd"  # key of all 'a' == no shift
    assert encode("a!b", "bc") == "b!d"
    assert encode("a1b", "bc") == "b1d"


def test_strict_alphabet_outputs_only_uppercase_letters():
    assert encode("Attack at dawn!", "lemon", alphabet="strict") == "LXFOPVEFRNHR"
    assert decode("LXFOPVEFRNHR", "lemon", alphabet="strict") == "ATTACKATDAWN"


def test_strict_alphabet_roundtrip_on_portuguese_text():
    message = "Ataque ao amanhecer, à meia-noite!"
    key = "segredo"
    ciphered = encode(message, key, alphabet="strict")
    assert ciphered.isalpha() and ciphered.isupper()
    assert decode(ciphered, key, alphabet="strict") == "ATAQUEAOAMANHECERAMEIANOITE"


def test_unknown_alphabet_raises():
    with pytest.raises(ValueError):
        encode("hello", "key", alphabet="ascii")


def test_key_ignores_non_alpha_characters():
    assert encode("attack", "l3e!m") == encode("attack", "lem")


def test_key_accepts_portuguese_letters():
    assert encode("attack", "limão") == encode("attack", "limao")


def test_effective_key():
    assert effective_key("L3E!Mão") == "lemao"


def test_count_letters():
    assert count_letters("Olá, 123 mundo!") == 8


def test_empty_key_raises():
    with pytest.raises(ValueError):
        encode("hello", "123")
