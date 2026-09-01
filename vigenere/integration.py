from __future__ import annotations

import string
from collections import Counter
from dataclasses import dataclass, field

if __package__ in (None, ""):
    import sys
    from pathlib import Path

    sys.path.append(str(Path(__file__).resolve().parent.parent))
    from vigenere.attack import (
        ENGLISH_FREQ,
        PORTUGUESE_FREQ,
        calculate_ic,
        recover_key,
    )
    from vigenere.cipher import decode, encode
else:
    from .attack import (
        ENGLISH_FREQ,
        PORTUGUESE_FREQ,
        calculate_ic,
        recover_key,
    )
    from .cipher import decode, encode

LIMIAR_ACEITACAO = 0.55

_COMMON_WORDS = {
    "pt": {
        "de", "a", "o", "que", "e", "do", "da", "em", "um", "para", "com",
        "uma", "os", "no", "se", "na", "por", "mais", "as", "dos", "como",
        "mas", "ao", "ele", "das", "seu", "sua", "ou", "quando", "muito",
        "nos", "ja", "eu", "tambem", "so", "pelo", "pela", "ate", "isso",
        "ela", "entre", "depois", "sem", "mesmo", "aos", "seus", "quem",
        "nas", "me", "esse", "eles", "voce", "essa", "num", "nem", "suas",
        "meu", "minha", "numa", "pelos", "elas", "qual", "lhe", "deles",
        "essas", "esses", "pelas", "este", "dele", "tu", "te", "nao",
    },
    "en": {
        "the", "of", "and", "a", "to", "in", "is", "you", "that", "it",
        "he", "was", "for", "on", "are", "as", "with", "his", "they",
        "at", "be", "this", "have", "from", "or", "one", "had", "by",
        "word", "but", "not", "what", "all", "were", "we", "when", "your",
        "can", "said", "there", "use", "an", "each", "which", "she", "do",
        "how", "their", "if", "will", "up", "other", "about", "out",
        "many", "then", "them", "these", "so", "some", "her", "would",
    },
}

def _freq_for(idioma: str) -> dict:
    """
    Retorna a tabela de frequência de letras do idioma indicado ("pt" ou "en").
    """
    return PORTUGUESE_FREQ if idioma == "pt" else ENGLISH_FREQ

def _clean_for_analysis(ciphertext: str) -> str:
    """
    Reduz o criptograma a uma sequência só de letras A-Z maiúsculas, sem
    espaços, pontuação ou acentos, mantendo a ordem original. Necessário
    porque a análise por colunas fatia o texto por posição.
    """
    return encode(ciphertext, "a", alphabet="strict")


def _split_columns(text: str, key_length: int) -> list[str]:
    """
    Separa o texto em key_length colunas (uma por posição da chave),
    já que letras em posições múltiplas de key_length compartilham a
    mesma letra de deslocamento.
    """
    return [text[i::key_length] for i in range(key_length)]

# Candidatos ranqueados (não só "o melhor").

def _candidate_key_lengths(
    cleaned: str, max_length: int, top_n: int
) -> list[tuple[int, float]]:
    """"
    Testa comprimentos de chave de 1 até max_length e devolve os top_n
    com maior índice de coincidência médio das colunas — os mais
    prováveis de serem o comprimento real.
    """
    pontuacoes = []
    for k in range(1, max_length + 1):
        colunas = _split_columns(cleaned, k)
        ic_medio = sum(calculate_ic(col) for col in colunas) / k
        pontuacoes.append((k, ic_medio))

    pontuacoes.sort(key=lambda item: item[1], reverse=True)
    return pontuacoes[:top_n]


def _shift_candidates(
    column: str, freq: dict, top_n: int
) -> list[tuple[str, float]]:
    """
    Testa os 26 deslocamentos possíveis numa coluna e devolve os top_n
    com menor qui-quadrado contra freq — as letras de chave mais
    prováveis para essa posição.
    """
    tamanho_coluna = len(column)
    resultados = []

    for deslocamento in range(26):
        decifrado = [
            chr((ord(char) - ord("A") - deslocamento) % 26 + ord("A"))
            for char in column
        ]
        contagem = Counter(decifrado)

        qui_quadrado = 0.0
        for letra in string.ascii_uppercase:
            observado = contagem.get(letra, 0)
            esperado = tamanho_coluna * freq.get(letra, 0.0)
            if esperado > 0:
                qui_quadrado += ((observado - esperado) ** 2) / esperado

        resultados.append((chr(deslocamento + ord("A")), qui_quadrado))

    resultados.sort(key=lambda item: item[1])
    return resultados[:top_n]


"""
Avaliação de "o texto decifrado faz sentido?"
"""

def _chi_squared_text(text: str, freq: dict) -> float:
    """
    Qui-quadrado compara as frequências observadas em um experimento 
    com as frequências esperadas caso o acaso estivesse governando os dados.
    Qui-quadrado (normalizado pelo tamanho) entre a distribuição de
    letras do texto e freq. Quanto menor, mais parecido com o idioma.
    """
    letras = [c for c in text.upper() if c in string.ascii_uppercase]
    n = len(letras)
    if n == 0:
        return float("inf")

    contagem = Counter(letras)
    qui_quadrado = 0.0
    for letra in string.ascii_uppercase:
        observado = contagem.get(letra, 0)
        esperado = n * freq.get(letra, 0.0)
        if esperado > 0:
            qui_quadrado += ((observado - esperado) ** 2) / esperado
    return qui_quadrado / n


def _common_word_ratio(text: str, idioma: str) -> float:
    """
    Fração das palavras do texto que estão na lista de palavras comuns
    do idioma — um sinal lexical simples, complementar ao qui-quadrado.
    """
    bruto = "".join(c if c.isalpha() else " " for c in text)
    palavras = [w.lower() for w in bruto.split()]
    if not palavras:
        return 0.0

    comuns = _COMMON_WORDS[idioma]
    acertos = sum(1 for w in palavras if w in comuns)
    return acertos / len(palavras)


def _score_candidate(plaintext: str, idioma: str) -> float:
    """
    Combina qui-quadrado (invertido para (0,1]) e fração de palavras
    comuns num único score, onde maior sempre significa mais plausível.
    """
    freq = _freq_for(idioma)
    qui_quadrado = _chi_squared_text(plaintext, freq)
    proporcao_palavras = _common_word_ratio(plaintext, idioma)
    return 1.0 / (1.0 + qui_quadrado) + proporcao_palavras


# Registro do processo de busca (mostra o "caminho" percorrido, não só a resposta final).

@dataclass
class Tentativa:
    """Uma tentativa de decifração testada durante o ataque."""

    idioma: str
    tamanho_chave: int
    ic_medio: float
    chave: str
    texto: str
    score: float
    refinada: bool = False


@dataclass
class ResultadoAtaque:
    """Resultado completo: a melhor tentativa e o histórico de todas."""

    melhor: Tentativa
    tentativas: list[Tentativa] = field(default_factory=list)


def _log_tentativa(tentativa: Tentativa) -> None:
    """
    Imprime no console um resumo de uma tentativa de decifração (idioma,
    comprimento, chave, score e se veio de um ajuste).
    """
    etapa = "refinamento" if tentativa.refinada else "tentativa inicial"
    print(
        f"[{tentativa.idioma}] tamanho={tentativa.tamanho_chave} "
        f"(IC médio das colunas={tentativa.ic_medio:.4f}) -> "
        f"chave='{tentativa.chave}' | score={tentativa.score:.3f} ({etapa})"
    )

# Pipeline picinpal.

def _tentar_idioma_e_tamanho(
    cleaned: str, original: str, idioma: str, tamanho: int, ic_medio: float
) -> Tentativa:
    """
    Recupera uma chave candidata, decifra o texto com ela e avalia a
    plausibilidade do resultado, para um idioma e comprimento fixos.
    """
    freq = _freq_for(idioma)

    chave = recover_key(cleaned, tamanho, freq)
    texto = decode(original, chave, alphabet="preserve")
    score = _score_candidate(texto, idioma)

    return Tentativa(idioma, tamanho, ic_medio, chave, texto, score)


def _refinar(
    cleaned: str, original: str, tentativa: Tentativa, top_n_por_posicao: int = 3
) -> Tentativa:
    """
    Testa, posição por posição, letras alternativas de chave, mantendo
    a troca só quando ela melhora o score do texto decifrado inteiro —
    busca local que nunca piora a chave, só melhora ou mantém.
    """
    freq = _freq_for(tentativa.idioma)
    colunas = _split_columns(cleaned, tentativa.tamanho_chave)

    melhor_chave = list(tentativa.chave)
    melhor_score = tentativa.score

    for posicao, coluna in enumerate(colunas):
        candidatos = _shift_candidates(coluna, freq, top_n_por_posicao)
        for letra_candidata, _qui_quadrado in candidatos:
            if letra_candidata.lower() == melhor_chave[posicao]:
                continue  # já é a letra atual nessa posição

            chave_teste = melhor_chave.copy()
            chave_teste[posicao] = letra_candidata.lower()
            chave_teste_str = "".join(chave_teste)

            texto_teste = decode(original, chave_teste_str, alphabet="preserve")
            score_teste = _score_candidate(texto_teste, tentativa.idioma)

            if score_teste > melhor_score:
                melhor_chave = chave_teste
                melhor_score = score_teste

    chave_final = "".join(melhor_chave)
    texto_final = decode(original, chave_final, alphabet="preserve")
    return Tentativa(
        idioma=tentativa.idioma,
        tamanho_chave=tentativa.tamanho_chave,
        ic_medio=tentativa.ic_medio,
        chave=chave_final,
        texto=texto_final,
        score=melhor_score,
        refinada=True,
    )


def resolver_criptograma(
    ciphertext: str,
    idiomas: tuple[str, ...] = ("pt", "en"),
    max_key_length: int = 20,
    n_tamanhos_candidatos: int = 3,
    limiar: float = LIMIAR_ACEITACAO,
    verbose: bool = True,
) -> ResultadoAtaque:
    """
    Estima o comprimento da chave, testa cada idioma e comprimento
    candidato, decifra e avalia o resultado, ajustando a chave quando o
    score fica abaixo de limiar. Devolve a melhor tentativa e o histórico
    de todas.
    """
    cleaned = _clean_for_analysis(ciphertext)
    tamanhos_candidatos = _candidate_key_lengths(
        cleaned, max_key_length, n_tamanhos_candidatos
    )

    tentativas: list[Tentativa] = []

    for idioma in idiomas:
        for tamanho, ic_medio in tamanhos_candidatos:
            tentativa = _tentar_idioma_e_tamanho(
                cleaned, ciphertext, idioma, tamanho, ic_medio
            )
            tentativas.append(tentativa)
            if verbose:
                _log_tentativa(tentativa)

            if tentativa.score < limiar:
                refinada = _refinar(cleaned, ciphertext, tentativa)
                tentativas.append(refinada)
                if verbose:
                    _log_tentativa(refinada)

    melhor = max(tentativas, key=lambda t: t.score)

    if verbose:
        print("\n=== Melhor resultado encontrado ===")
        print(
            f"Idioma: {melhor.idioma} | Tamanho da chave: {melhor.tamanho_chave} "
            f"| Chave: {melhor.chave} | Score: {melhor.score:.3f}"
        )
        print(f"\nTexto decifrado: {melhor.texto}")

    return ResultadoAtaque(melhor=melhor, tentativas=tentativas)


"""
Interface interativa (menu): Um menu simples em linha de 
comando que primeiro pergunta o idioma, depois a operação desejada, 
e então pede o texto (e a chave, quando aplicável) por meio de input()
"""

_IDIOMAS = {"pt": "Português", "en": "Inglês"}
_OPERACOES = {
    "cifrar": "Cifrar um texto (chave conhecida)",
    "decifrar": "Decifrar um texto (chave conhecida)",
    "atacar": "Atacar um criptograma (chave desconhecida - criptoanálise)",
}


def _escolher(titulo: str, opcoes: dict[str, str]) -> str:
    chaves = list(opcoes.keys())

    while True:
        print(titulo)
        for numero, chave in enumerate(chaves, start=1):
            print(f"  {numero}. {opcoes[chave]}")

        escolha = input("> ").strip()
        if escolha.isdigit() and 1 <= int(escolha) <= len(chaves):
            return chaves[int(escolha) - 1]

        print(f"\nOpção inválida. Digite 1 ou {len(chaves)}.\n")


def _executar_cifrar_ou_decifrar(operacao: str) -> None:
    texto = input("Digite o texto: ")
    chave = input("Digite a chave: ")

    try:
        if operacao == "cifrar":
            resultado = encode(texto, chave, alphabet="preserve")
            rotulo = "Criptograma"
        else:
            resultado = decode(texto, chave, alphabet="preserve")
            rotulo = "Texto claro"
    except ValueError as erro:
        print(f"\nErro na entrada: {erro}\n")
        return

    print(f"\n{rotulo}: {resultado}\n")


def _executar_ataque(idioma: str) -> None:
    criptograma = input("Digite o criptograma a ser atacado: ")

    print("\nAnalisando o criptograma (estimando tamanho de chave, testando candidatos)...\n")

    resolver_criptograma(criptograma, idiomas=(idioma,), verbose=True)

def main() -> int:
    print("\n\033[33m===\033[m \033[32mCifra de Vigenère\033[m \033[33m===\033[m\n") # Título colorido, só de zoas

    while True:
        idioma = _escolher("Selecione o idioma do texto:", _IDIOMAS)
        print()
        operacao = _escolher("Selecione a operação:", _OPERACOES)
        print()

        if operacao in ("cifrar", "decifrar"):
            _executar_cifrar_ou_decifrar(operacao)
        else:
            _executar_ataque(idioma)

        de_novo = input("\nDeseja realizar outra operação? (s/n): ").strip().lower()
        print()
        if de_novo != "s":
            print("Encerrando o programa. Até mais!")
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
