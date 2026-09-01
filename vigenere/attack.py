"""Primitivas de criptoanálise da cifra de Vigenère (Parte II).

Este módulo reúne as ferramentas estatísticas do ataque, cada uma
correspondendo a uma etapa pedida no enunciado:

- :func:`calculate_ic` — índice de coincidência de um texto;
- :func:`split_columns` — separação do criptograma nos subconjuntos
  associados às posições da chave;
- :func:`candidate_key_lengths` — estimativa dos comprimentos de chave
  mais prováveis, via IC médio das colunas;
- :func:`shift_candidates` — análise de frequência de uma coluna contra a
  distribuição esperada do idioma, pela estatística qui-quadrado;
- :func:`find_key_character` e :func:`recover_key` — obtenção dos
  caracteres da chave e reconstrução da chave completa.

A orquestração do ataque (testar idiomas e comprimentos, avaliar o texto
decifrado e refinar a chave) fica em :mod:`vigenere.integration`.
"""

from collections import Counter
import string


# Frequências aproximadas da língua portuguesa (segundo a referência do trabalho)
PORTUGUESE_FREQ = {
    'A': 0.1463, 'B': 0.0104, 'C': 0.0388, 'D': 0.0499, 'E': 0.1257,
    'F': 0.0102, 'G': 0.0130, 'H': 0.0128, 'I': 0.0618, 'J': 0.0040,
    'K': 0.0002, 'L': 0.0278, 'M': 0.0474, 'N': 0.0505, 'O': 0.1073,
    'P': 0.0252, 'Q': 0.0120, 'R': 0.0653, 'S': 0.0781, 'T': 0.0434,
    'U': 0.0463, 'V': 0.0167, 'W': 0.0001, 'X': 0.0021, 'Y': 0.0001,
    'Z': 0.0047
}

# Frequências aproximadas da língua inglesa
ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0198,
    'Z': 0.0007
}


def calculate_ic(text: str) -> float:
    """Calcula o Índice de Coincidência (IC) de uma string."""
    N = len(text)

    # Textos com 1 ou 0 caracteres não têm pares para comparar
    if N <= 1:
        return 0.0

    counts = Counter(text)

    # Aplicação direta da fórmula matemática
    numerator = sum(n * (n - 1) for n in counts.values())
    denominator = N * (N - 1)

    return numerator / denominator


def split_columns(text: str, key_length: int) -> list[str]:
    """Separa ``text`` em ``key_length`` colunas, uma por posição da chave.

    Letras em posições congruentes módulo ``key_length`` foram cifradas
    pela mesma letra da chave, ou seja, pelo mesmo deslocamento. Cada
    coluna é portanto uma cifra de César, e é isso que torna possível
    atacá-las separadamente.
    """
    return [text[i::key_length] for i in range(key_length)]


def candidate_key_lengths(
    ciphertext: str, max_length: int = 20, top_n: int = 3
) -> list[tuple[int, float]]:
    """Estima os comprimentos de chave mais prováveis pelo IC médio das colunas.

    Testa cada comprimento de 1 até ``max_length``, separa o criptograma
    em colunas e calcula o IC médio delas. Uma coluna cifrada por um
    único deslocamento preserva o IC da linguagem natural (≈ 0,078 no
    português, ≈ 0,065 no inglês); um comprimento errado mistura
    deslocamentos diferentes e o IC cai para ≈ 0,038, o de uma
    distribuição uniforme.

    Devolve os ``top_n`` melhores como pares ``(comprimento, ic_médio)``,
    em ordem decrescente de IC. Devolver vários candidatos (em vez de só
    o melhor) é importante porque qualquer múltiplo do comprimento real
    também produz colunas de César válidas, e portanto também apresenta
    IC alto.
    """
    scores = []
    for k in range(1, max_length + 1):
        columns = split_columns(ciphertext, k)
        avg_ic = sum(calculate_ic(col) for col in columns) / k
        scores.append((k, avg_ic))

    scores.sort(key=lambda item: item[1], reverse=True)
    return scores[:top_n]


def shift_candidates(
    column: str, language_freq: dict = PORTUGUESE_FREQ, top_n: int = 1
) -> list[tuple[str, float]]:
    """Ranqueia as letras de chave mais prováveis para uma coluna.

    Testa os 26 deslocamentos possíveis: decifra a coluna com cada um e
    compara a distribuição resultante com ``language_freq`` pela
    estatística qui-quadrado

        χ² = Σ (observado - esperado)² / esperado

    Quanto menor o χ², mais a coluna decifrada se parece com o idioma.
    Devolve os ``top_n`` melhores como pares ``(letra, qui_quadrado)``,
    em ordem crescente de χ².
    """
    col_length = len(column)
    results = []

    # Testar cada letra de 'A' a 'Z' como possível chave para esta coluna
    for shift in range(26):
        # Desloca as letras da coluna para trás (decifração)
        decrypted_col = []
        for char in column:
            # P_i = (C_i - K_i) mod 26
            shifted_ord = (ord(char) - ord('A') - shift) % 26 + ord('A')
            decrypted_col.append(chr(shifted_ord))

        counts = Counter(decrypted_col)

        # Calcula o Qui-quadrado para este deslocamento
        chi_sq = 0.0
        for letter in string.ascii_uppercase:
            observed = counts.get(letter, 0)
            expected = col_length * language_freq.get(letter, 0.0)

            # Evita divisão por zero para letras com frequência zero
            if expected > 0:
                chi_sq += ((observed - expected) ** 2) / expected

        results.append((chr(shift + ord('A')), chi_sq))

    results.sort(key=lambda item: item[1])
    return results[:top_n]


def find_key_character(column: str, language_freq: dict = PORTUGUESE_FREQ) -> str:
    """Devolve a letra de chave mais provável para uma coluna.

    É o melhor candidato de :func:`shift_candidates`, isto é, o
    deslocamento que minimiza a estatística qui-quadrado.
    """
    return shift_candidates(column, language_freq, top_n=1)[0][0]


def recover_key(ciphertext: str, key_length: int, language_freq: dict = PORTUGUESE_FREQ) -> str:
    """Reconstrói a chave completa, dada uma estimativa do seu comprimento.

    Separa o criptograma em colunas e resolve cada uma independentemente
    como uma cifra de César, usando as frequências do idioma indicado.
    """
    key = ""

    for col in split_columns(ciphertext, key_length):
        # Repassa o idioma escolhido para a função de Qui-quadrado
        key += find_key_character(col, language_freq)

    return key
