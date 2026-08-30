"""Lógica central da cifra de Vigenère.

A cifra opera sobre o alfabeto clássico de 26 letras ``A-Z``. Todo caractere da
entrada é primeiro *reduzido* a esse alfabeto:

- letras ASCII ``a-z`` / ``A-Z`` são usadas como estão;
- letras acentuadas são decompostas (Unicode NFD) e reduzidas à sua letra base,
  de modo que ``é -> e``, ``ç -> c``, ``ã -> a``, ``Ó -> O``. O acento é,
  portanto, **perdido**: ao decifrar obtém-se ``acao``, e não ``ação``;
- qualquer outro caractere (espaços, dígitos, pontuação) não pertence ao
  alfabeto.

O tratamento dos caracteres fora do alfabeto depende do modo ``alphabet``:

``preserve`` (padrão)
    São copiados para a saída sem alteração e **não** consomem uma letra da
    chave. Maiúsculas e minúsculas são preservadas. É conveniente para ler o
    resultado, mas a pontuação e o espaçamento do texto claro continuam
    visíveis no criptograma.

``strict``
    São descartados. A saída é uma sequência contínua de letras ``A-Z``
    maiúsculas, o formato usual dos exercícios clássicos de criptoanálise.

O núcleo matemático está em :func:`_transform`:
    cifração:   C_i = (P_i + K_i) mod 26
    decifração: P_i = (C_i - K_i) mod 26
onde ``i`` conta apenas as letras da mensagem e ``K`` se repete ciclicamente.
"""

import unicodedata

ALPHABET_SIZE = 26
ALPHABETS = ("preserve", "strict")


def fold(char: str) -> str | None:
    """Reduz ``char`` ao alfabeto A-Z.

    Devolve a letra ASCII base, mantendo maiúscula/minúscula, ou ``None`` quando
    o caractere não é uma letra do alfabeto. Letras acentuadas são normalizadas
    com NFD, que separa por exemplo ``ç`` em ``c`` + cedilha combinante, de modo
    que o primeiro ponto de código é a letra base.
    """
    base = unicodedata.normalize("NFD", char)[:1]
    if "a" <= base <= "z" or "A" <= base <= "Z":
        return base
    return None


def key_offsets(key: str) -> list[int]:
    """Devolve a chave como uma lista de deslocamentos 0-25, ignorando o que não é letra."""
    offsets = [
        ord(letter.lower()) - ord("a")
        for letter in (fold(char) for char in key)
        if letter is not None
    ]
    if not offsets:
        raise ValueError("A chave deve conter ao menos uma letra (A-Z).")
    return offsets


def effective_key(key: str) -> str:
    """Devolve a chave realmente usada: reduzida a A-Z, minúscula, apenas letras."""
    return "".join(chr(offset + ord("a")) for offset in key_offsets(key))


def count_letters(text: str) -> int:
    """Quantidade de caracteres de ``text`` que pertencem ao alfabeto A-Z."""
    return sum(1 for char in text if fold(char) is not None)


def _transform(text: str, key: str, sign: int, alphabet: str) -> str:
    """Desloca as letras de ``text`` pela chave. ``sign`` é +1 para cifrar, -1 para decifrar."""
    if alphabet not in ALPHABETS:
        raise ValueError(
            f"Modo de alfabeto desconhecido: {alphabet!r}; "
            f"esperado um entre {', '.join(ALPHABETS)}."
        )

    offsets = key_offsets(key)
    result = []
    key_index = 0  # avança só nas letras, mantendo a chave sincronizada

    for char in text:
        letter = fold(char)

        if letter is None:
            # Fora do alfabeto: mantido tal e qual (sem avançar a chave) no modo
            # "preserve", descartado no modo "strict".
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
    """Cifra ``plaintext`` com ``key`` e devolve o criptograma."""
    return _transform(plaintext, key, sign=1, alphabet=alphabet)


def decode(ciphertext: str, key: str, alphabet: str = "preserve") -> str:
    """Decifra ``ciphertext`` com ``key`` e devolve o texto claro."""
    return _transform(ciphertext, key, sign=-1, alphabet=alphabet)
