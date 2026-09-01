"""Testes das primitivas de criptoanálise (Parte II)."""

import string

import pytest

from vigenere.attack import (
    ENGLISH_FREQ,
    PORTUGUESE_FREQ,
    calculate_ic,
    candidate_key_lengths,
    find_key_character,
    recover_key,
    shift_candidates,
    split_columns,
)
from vigenere.cipher import encode

from textos import ENGLISH_TEXT, PORTUGUESE_TEXT


def _strict(text):
    """Reduz um texto a letras A-Z maiúsculas, como o ataque faz."""
    return encode(text, "a", alphabet="strict")


# --- Tabelas de frequência ---------------------------------------------------


@pytest.mark.parametrize(
    "table", [PORTUGUESE_FREQ, ENGLISH_FREQ], ids=["pt", "en"]
)
def test_frequency_tables_cover_the_alphabet_and_sum_to_one(table):
    assert set(table) == set(string.ascii_uppercase)
    # Tabelas aproximadas: tolerância de 1% na soma.
    assert sum(table.values()) == pytest.approx(1.0, abs=0.01)


# --- Índice de coincidência --------------------------------------------------


def test_ic_of_text_too_short_to_have_pairs_is_zero():
    assert calculate_ic("") == 0.0
    assert calculate_ic("A") == 0.0


def test_ic_of_a_single_repeated_letter_is_one():
    # Todos os pares coincidem, o máximo possível.
    assert calculate_ic("AAAAAA") == 1.0


def test_ic_of_all_distinct_letters_is_zero():
    # Nenhum par coincide.
    assert calculate_ic(string.ascii_uppercase) == 0.0


@pytest.mark.parametrize(
    "text, expected_ic",
    [(PORTUGUESE_TEXT, 0.078), (ENGLISH_TEXT, 0.065)],
    ids=["pt", "en"],
)
def test_ic_of_natural_language_is_near_the_theoretical_value(text, expected_ic):
    # O IC de linguagem natural fica muito acima do de uma distribuição
    # uniforme (1/26 ≈ 0,038); é essa diferença que o ataque explora.
    assert calculate_ic(_strict(text)) == pytest.approx(expected_ic, abs=0.015)


def test_vigenere_lowers_the_ic_of_the_text():
    claro = _strict(PORTUGUESE_TEXT)
    cifrado = encode(claro, "chavelonga", alphabet="strict")
    # Misturar vários deslocamentos aproxima a distribuição da uniforme.
    assert calculate_ic(cifrado) < calculate_ic(claro)


def test_caesar_cipher_preserves_the_ic():
    # Uma chave de uma letra é uma cifra de César: apenas permuta o
    # alfabeto, então o IC é exatamente o mesmo. É essa propriedade que
    # permite atacar cada coluna separadamente.
    claro = _strict(PORTUGUESE_TEXT)
    assert calculate_ic(encode(claro, "k", alphabet="strict")) == pytest.approx(
        calculate_ic(claro)
    )


# --- Separação em colunas ----------------------------------------------------


def test_split_columns_distributes_by_position():
    assert split_columns("ABCDEFGH", 3) == ["ADG", "BEH", "CF"]


def test_split_columns_with_length_one_returns_the_whole_text():
    assert split_columns("ABCDEF", 1) == ["ABCDEF"]


def test_split_columns_preserves_every_letter():
    texto = _strict(PORTUGUESE_TEXT)
    for k in (1, 3, 7, 20):
        colunas = split_columns(texto, k)
        assert len(colunas) == k
        assert sum(len(c) for c in colunas) == len(texto)


# --- Estimativa do comprimento da chave --------------------------------------


def test_candidate_key_lengths_returns_ranked_pairs():
    cifrado = encode(_strict(PORTUGUESE_TEXT), "segredo", alphabet="strict")
    candidatos = candidate_key_lengths(cifrado, max_length=20, top_n=5)

    assert len(candidatos) == 5
    # Pares (comprimento, ic), em ordem decrescente de IC.
    ics = [ic for _k, ic in candidatos]
    assert ics == sorted(ics, reverse=True)
    assert all(1 <= k <= 20 for k, _ic in candidatos)


@pytest.mark.parametrize("key", ["ab", "lemon", "segredo", "chaveextensa"])
def test_candidate_key_lengths_finds_a_multiple_of_the_real_length(key):
    # Qualquer múltiplo do comprimento real também separa o texto em
    # colunas de César válidas, e portanto também apresenta IC alto. O
    # ataque testa vários candidatos justamente por isso.
    cifrado = encode(_strict(PORTUGUESE_TEXT), key, alphabet="strict")
    candidatos = candidate_key_lengths(cifrado, max_length=20, top_n=3)

    assert any(k % len(key) == 0 for k, _ic in candidatos)


def test_real_key_length_has_higher_ic_than_a_wrong_one():
    cifrado = encode(_strict(PORTUGUESE_TEXT), "segredo", alphabet="strict")
    por_comprimento = dict(candidate_key_lengths(cifrado, max_length=20, top_n=20))

    # 7 é o comprimento real; 6 e 8 não são múltiplos dele.
    assert por_comprimento[7] > por_comprimento[6]
    assert por_comprimento[7] > por_comprimento[8]


# --- Análise de frequência por coluna ----------------------------------------


@pytest.mark.parametrize("letra_chave", ["A", "K", "S", "Z"])
def test_find_key_character_recovers_a_known_caesar_shift(letra_chave):
    coluna = encode(_strict(PORTUGUESE_TEXT), letra_chave, alphabet="strict")
    assert find_key_character(coluna, PORTUGUESE_FREQ) == letra_chave


def test_find_key_character_uses_the_language_table():
    coluna = encode(_strict(ENGLISH_TEXT), "Q", alphabet="strict")
    assert find_key_character(coluna, ENGLISH_FREQ) == "Q"


def test_shift_candidates_returns_ranked_pairs():
    coluna = encode(_strict(PORTUGUESE_TEXT), "S", alphabet="strict")
    candidatos = shift_candidates(coluna, PORTUGUESE_FREQ, top_n=26)

    assert len(candidatos) == 26
    # Ordem crescente de qui-quadrado: o primeiro é o mais provável.
    quis = [chi for _letra, chi in candidatos]
    assert quis == sorted(quis)
    assert candidatos[0][0] == "S"
    # Todas as 26 letras aparecem exatamente uma vez.
    assert {letra for letra, _chi in candidatos} == set(string.ascii_uppercase)


def test_shift_candidates_defaults_to_the_single_best():
    coluna = encode(_strict(PORTUGUESE_TEXT), "S", alphabet="strict")
    assert shift_candidates(coluna) == shift_candidates(coluna, PORTUGUESE_FREQ, 1)
    assert len(shift_candidates(coluna)) == 1


# --- Reconstrução da chave ---------------------------------------------------


@pytest.mark.parametrize(
    "text, table, key",
    [
        (PORTUGUESE_TEXT, PORTUGUESE_FREQ, "SEGREDO"),
        (PORTUGUESE_TEXT, PORTUGUESE_FREQ, "AB"),
        (ENGLISH_TEXT, ENGLISH_FREQ, "LEMON"),
    ],
)
def test_recover_key_finds_a_known_key(text, table, key):
    cifrado = encode(_strict(text), key, alphabet="strict")
    assert recover_key(cifrado, len(key), table) == key


def test_recover_key_returns_one_letter_per_key_position():
    cifrado = encode(_strict(PORTUGUESE_TEXT), "segredo", alphabet="strict")
    for comprimento in (1, 5, 7, 14):
        assert len(recover_key(cifrado, comprimento, PORTUGUESE_FREQ)) == comprimento
