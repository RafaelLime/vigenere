"""Ataque automático completo à cifra de Vigenère (Parte II).

Orquestra as primitivas estatísticas de :mod:`vigenere.attack` num ataque
de ponta a ponta: estima os comprimentos de chave mais prováveis, testa
cada idioma e comprimento candidato, decifra, avalia se o texto obtido
faz sentido e refina a chave quando o resultado é fraco.

Além do resultado final, devolve todos os resultados intermediários
(:class:`ResultadoAtaque`): a tabela de IC por comprimento de chave, o
histórico de cada tentativa, a evidência por coluna que sustenta cada
letra da chave e as trocas feitas no refinamento. Com ``verbose=True``
tudo isso é impresso etapa por etapa — o enunciado pede que hipóteses
testadas e justificativas fiquem visíveis, não apenas a resposta.

Também expõe o menu interativo do programa (:func:`main`), executável com
``python -m vigenere.integration``.
"""

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
        ColumnReport,
        analyze_columns,
        calculate_ic,
        key_length_scores,
        shift_candidates,
        split_columns,
    )
    from vigenere.cipher import decode, encode
else:
    from .attack import (
        ENGLISH_FREQ,
        PORTUGUESE_FREQ,
        ColumnReport,
        analyze_columns,
        calculate_ic,
        key_length_scores,
        shift_candidates,
        split_columns,
    )
    from .cipher import decode, encode

LIMIAR_ACEITACAO = 0.55

# Amostra mínima por coluna para a análise de frequência ser confiável.
# Cada coluna é atacada isoladamente contra uma distribuição de 26 letras;
# com poucas letras o qui-quadrado deixa de medir o idioma e passa a
# ajustar ruído, produzindo um texto que imita as frequências esperadas
# sem ser linguagem real.
MIN_LETRAS_POR_COLUNA = 20

# Tolerância na comparação entre o IC do texto decifrado e o IC teórico do
# idioma, como fração desse valor.
TOLERANCIA_IC = 0.25

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
class Troca:
    """Uma substituição aceita pelo refinamento, com o ganho que a justificou."""

    posicao: int
    de: str
    para: str
    score_antes: float
    score_depois: float


@dataclass
class Tentativa:
    """Uma tentativa de decifração testada durante o ataque.

    Além do resultado (``chave``, ``texto``, ``score``), carrega a
    evidência que o produziu: ``colunas`` traz, por posição da chave, as
    frequências observadas e os candidatos disputados; ``trocas`` registra
    o que o refinamento mudou e por quê.
    """

    idioma: str
    tamanho_chave: int
    ic_medio: float
    chave: str
    texto: str
    score: float
    refinada: bool = False
    colunas: list[ColumnReport] = field(default_factory=list)
    trocas: list[Troca] = field(default_factory=list)


@dataclass
class ResultadoAtaque:
    """Resultado completo: a melhor tentativa e todo o caminho até ela.

    ``ic_por_tamanho`` é a tabela de IC médio de *todos* os comprimentos
    examinados, da qual saíram os candidatos testados; ``total_letras`` é
    o tamanho do criptograma normalizado, que determina quantas letras
    cada coluna recebeu.
    """

    melhor: Tentativa
    tentativas: list[Tentativa] = field(default_factory=list)
    alertas: list[str] = field(default_factory=list)
    ic_por_tamanho: list[tuple[int, float]] = field(default_factory=list)
    total_letras: int = 0

    @property
    def confiavel(self) -> bool:
        """``False`` quando o resultado não deve ser tomado como a resposta."""
        return not self.alertas


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

def _log_normalizacao(original: str, cleaned: str) -> None:
    """Etapa 1: o que sobrou do criptograma e o que seu IC já revela."""
    ic = calculate_ic(cleaned)
    print(
        f"{len(cleaned)} letras utilizáveis (A-Z) de {len(original)} caracteres.\n"
        f"IC do criptograma inteiro: {ic:.4f}  "
        f"(uniforme ≈ {1 / 26:.4f} | texto claro: pt ≈ {_ic_esperado('pt'):.4f}, "
        f"en ≈ {_ic_esperado('en'):.4f})"
    )
    if len(cleaned) < 2:
        # Sem pares de letras o IC não é definido; não há o que concluir.
        print("  -> letras insuficientes para uma análise estatística.")
        return

    if ic >= _ic_esperado("en") * (1 - TOLERANCIA_IC):
        print(
            "  -> IC alto, próximo ao de linguagem natural: compatível com uma "
            "chave de uma única letra (cifra de César)."
        )
    else:
        print(
            "  -> IC baixo, próximo ao uniforme: vários deslocamentos foram "
            "misturados, ou seja, a chave tem mais de uma letra."
        )


def _log_tabela_ic(
    ic_por_tamanho: list[tuple[int, float]], escolhidos: list[tuple[int, float]]
) -> None:
    """Etapa 2: a tabela de IC que justifica os comprimentos escolhidos.

    Mostra *todos* os comprimentos examinados, não apenas os vencedores:
    é o que permite ver o IC saltar nos múltiplos do comprimento real e
    ficar rente ao valor uniforme nos demais.
    """
    if not ic_por_tamanho:
        return

    candidatos = {tamanho for tamanho, _ic in escolhidos}
    ic_maximo = max(ic for _tamanho, ic in ic_por_tamanho)
    ic_uniforme = 1 / 26
    largura_barra = 28

    # A barra mede o *excesso* de IC sobre o valor de uma distribuição
    # uniforme, não o IC absoluto. Todo comprimento errado já parte de
    # ≈ 0,038; medir a partir daí é o que faz o sinal aparecer.
    escala = ic_maximo - ic_uniforme

    print(
        f"{'tam':>4}  {'IC médio':>9}   "
        f"excesso sobre o IC uniforme (≈ {ic_uniforme:.4f})"
    )
    for tamanho, ic in ic_por_tamanho:
        if escala > 0:
            blocos = max(0, round((ic - ic_uniforme) / escala * largura_barra))
        else:
            blocos = 0
        marca = "  <- candidato testado" if tamanho in candidatos else ""
        print(f"{tamanho:>4}  {ic:>9.4f}   {'#' * blocos}{marca}".rstrip())


def _log_colunas(tentativa: Tentativa) -> None:
    """Etapa 4: a análise de frequência que sustenta cada letra da chave.

    Por posição da chave: quantas letras a coluna tem, a letra escolhida,
    seu qui-quadrado, a folga sobre o segundo colocado, as letras mais
    frequentes da coluna (com o que cada uma decifra) e os candidatos
    seguintes. Colunas de folga pequena são marcadas: são as posições em
    que a chave pode estar errada.
    """
    if not tentativa.colunas:
        return

    print(
        f"Chave '{tentativa.chave}' ({tentativa.idioma}), posição por posição:\n"
        f"{'pos':>4} {'n':>5} {'letra':>6} {'χ²':>9} {'folga':>7}     "
        f"{'letras mais frequentes (cifra→claro)':<40} próximos candidatos"
    )

    for coluna in tentativa.colunas:
        deslocamento = ord(coluna.key_letter) - ord("A")
        # Mostrar o que as letras mais frequentes decifram torna visível o
        # raciocínio: a mais comum da coluna deve cair numa letra comum do
        # idioma ('A' ou 'E' em português).
        frequentes = "  ".join(
            f"{letra}→{chr((ord(letra) - ord('A') - deslocamento) % 26 + ord('A'))}"
            f" {fracao:.1%}"
            for letra, fracao in coluna.frequencies[:3]
        )
        proximos = " ".join(
            f"{letra}({chi:.1f})" for letra, chi in coluna.candidates[1:3]
        )
        # Folga pequena = empate técnico entre deslocamentos; é onde o
        # refinamento tem chance de corrigir a chave. Expressa como razão
        # ("o segundo colocado é 29x pior") em vez de porcentagem, que
        # nesses casos chega a quatro dígitos e deixa de comunicar.
        aviso = " (!)" if coluna.margin < 0.10 else ""

        print(
            (
                f"{coluna.position + 1:>4} {coluna.length:>5} {coluna.key_letter:>6} "
                f"{coluna.candidates[0][1]:>9.2f} {1 + coluna.margin:>6.1f}x{aviso:<4} "
                f"{frequentes:<40} {proximos}"
            ).rstrip()
        )

    indecisas = [c.position + 1 for c in tentativa.colunas if c.margin < 0.10]
    if indecisas:
        print(
            f"  (!) folga abaixo de 10% nas posições {indecisas}: o "
            "qui-quadrado não decidiu com clareza nessas colunas."
        )


def _log_trocas(tentativa: Tentativa) -> None:
    """Etapa 5: o que a busca local mudou, e o ganho que justificou cada troca."""
    if not tentativa.trocas:
        print("       nenhuma troca melhorou o score; a chave permaneceu igual.")
        return

    for troca in tentativa.trocas:
        print(
            f"       posição {troca.posicao + 1}: "
            f"'{troca.de}' -> '{troca.para}'  "
            f"(score {troca.score_antes:.3f} -> {troca.score_depois:.3f})"
        )


# Avaliação da confiança do resultado.
#
# O score serve para ordenar candidatos entre si, mas não diz se o melhor
# candidato é bom: o ataque sempre devolve algum resultado. As verificações
# abaixo detectam quando ele não tem base estatística para ser levado a
# sério, evitando que um texto ilegível seja apresentado como resposta.


def _ic_esperado(idioma: str) -> float:
    """IC teórico do idioma: soma dos quadrados das frequências das letras.

    É o valor que o IC de um texto claro nesse idioma tende a assumir
    (≈ 0,078 no português, ≈ 0,065 no inglês).
    """
    return sum(p * p for p in _freq_for(idioma).values())


def _alertas_de_confianca(tentativa: Tentativa, total_letras: int) -> list[str]:
    """Lista os motivos para desconfiar de uma tentativa; vazia se não houver.

    Duas verificações independentes:

    1. **Amostra por coluna.** Se o criptograma é curto (ou a chave longa),
       cada coluna tem poucas letras e o qui-quadrado superajusta.
    2. **IC do texto decifrado.** Um IC muito abaixo do esperado indica que
       a chave está errada e o texto continua misturando deslocamentos; um
       IC muito acima indica superajuste — o ataque forçou as colunas a
       imitar as frequências do idioma, o que não acontece em texto real.
    """
    alertas = []

    letras_por_coluna = total_letras / tentativa.tamanho_chave
    if letras_por_coluna < MIN_LETRAS_POR_COLUNA:
        alertas.append(
            f"apenas {letras_por_coluna:.1f} letras por coluna "
            f"(mínimo recomendado: {MIN_LETRAS_POR_COLUNA}) — a análise de "
            f"frequência não tem amostra suficiente para ser confiável"
        )

    ic_texto = calculate_ic(_clean_for_analysis(tentativa.texto))
    ic_ref = _ic_esperado(tentativa.idioma)
    if ic_texto < ic_ref * (1 - TOLERANCIA_IC):
        alertas.append(
            f"o índice de coincidência do texto decifrado ({ic_texto:.4f}) "
            f"está muito abaixo do esperado para '{tentativa.idioma}' "
            f"({ic_ref:.4f}) — a chave provavelmente está errada"
        )
    elif ic_texto > ic_ref * (1 + TOLERANCIA_IC):
        alertas.append(
            f"o índice de coincidência do texto decifrado ({ic_texto:.4f}) "
            f"está muito acima do esperado para '{tentativa.idioma}' "
            f"({ic_ref:.4f}) — sinal de que as colunas foram superajustadas"
        )

    return alertas


def _log_alertas(alertas: list[str]) -> None:
    """Imprime o aviso de baixa confiança que acompanha o resultado."""
    print("\n*** ATENÇÃO: resultado de baixa confiança ***")
    for alerta in alertas:
        print(f"  - {alerta}")
    print(
        "O texto abaixo provavelmente NÃO é o texto claro correto. "
        "Tente um criptograma mais longo ou ajuste max_key_length."
    )


# Pipeline principal.

def _tentar_idioma_e_tamanho(
    cleaned: str, original: str, idioma: str, tamanho: int, ic_medio: float
) -> Tentativa:
    """
    Recupera uma chave candidata, decifra o texto com ela e avalia a
    plausibilidade do resultado, para um idioma e comprimento fixos.
    """
    freq = _freq_for(idioma)

    # analyze_columns faz o mesmo que recover_key, mas devolve também a
    # evidência de cada coluna (frequências, candidatos, margem).
    colunas = analyze_columns(cleaned, tamanho, freq)
    chave = "".join(coluna.key_letter for coluna in colunas)
    texto = decode(original, chave, alphabet="preserve")
    score = _score_candidate(texto, idioma)

    return Tentativa(
        idioma, tamanho, ic_medio, chave, texto, score, colunas=colunas
    )


def _refinar(
    cleaned: str, original: str, tentativa: Tentativa, top_n_por_posicao: int = 3
) -> Tentativa:
    """
    Testa, posição por posição, letras alternativas de chave, mantendo
    a troca só quando ela melhora o score do texto decifrado inteiro —
    busca local que nunca piora a chave, só melhora ou mantém.
    """
    freq = _freq_for(tentativa.idioma)
    colunas = split_columns(cleaned, tentativa.tamanho_chave)

    # A chave vem em maiúsculas de analyze_columns; as substituições
    # seguem o mesmo caso, para que a chave exibida seja homogênea.
    melhor_chave = list(tentativa.chave.upper())
    melhor_score = tentativa.score
    trocas: list[Troca] = []

    for posicao, coluna in enumerate(colunas):
        candidatos = shift_candidates(coluna, freq, top_n_por_posicao)
        for letra_candidata, _qui_quadrado in candidatos:
            if letra_candidata == melhor_chave[posicao]:
                continue  # já é a letra atual nessa posição

            chave_teste = melhor_chave.copy()
            chave_teste[posicao] = letra_candidata
            chave_teste_str = "".join(chave_teste)

            texto_teste = decode(original, chave_teste_str, alphabet="preserve")
            score_teste = _score_candidate(texto_teste, tentativa.idioma)

            if score_teste > melhor_score:
                # Registra a troca aceita: é a justificativa da mudança
                # de chave, e o que diferencia esta tentativa da inicial.
                trocas.append(
                    Troca(
                        posicao=posicao,
                        de=melhor_chave[posicao],
                        para=letra_candidata,
                        score_antes=melhor_score,
                        score_depois=score_teste,
                    )
                )
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
        colunas=tentativa.colunas,
        trocas=trocas,
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
    score fica abaixo de limiar. Devolve a melhor tentativa, o histórico
    de todas e os alertas de confiança do resultado escolhido.

    O ataque sempre devolve algum resultado; consulte
    ``ResultadoAtaque.confiavel`` (ou ``.alertas``) para saber se ele tem
    base estatística para ser levado a sério.
    """
    # Etapa 1 — normalização.
    cleaned = _clean_for_analysis(ciphertext)
    if verbose:
        print("=== Etapa 1: normalização do criptograma ===")
        _log_normalizacao(ciphertext, cleaned)

    # Etapa 2 — estimativa do tamanho da chave. A tabela completa é
    # guardada (e impressa) porque é ela que justifica os candidatos; os
    # candidatos são simplesmente os melhores comprimentos dela.
    ic_por_tamanho = key_length_scores(cleaned, max_key_length)
    tamanhos_candidatos = sorted(
        ic_por_tamanho, key=lambda item: item[1], reverse=True
    )[:n_tamanhos_candidatos]
    if verbose:
        print("\n=== Etapa 2: estimativa do tamanho da chave (índice de coincidência) ===")
        _log_tabela_ic(ic_por_tamanho, tamanhos_candidatos)

    # Etapa 3 — recuperação da chave para cada idioma e comprimento
    # candidato, com refinamento (etapa 5) das tentativas fracas.
    if verbose:
        print("\n=== Etapa 3: recuperação da chave por idioma e comprimento ===")

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
                    _log_trocas(refinada)

    melhor = max(tentativas, key=lambda t: t.score)
    alertas = _alertas_de_confianca(melhor, len(cleaned))

    if verbose:
        # A evidência por coluna da tentativa vencedora — o detalhe da
        # etapa 3, não uma etapa nova. Fica no fim, e só para a vencedora,
        # para não afogar a saída: as demais já foram justificadas pelo
        # score acima.
        print(
            "\n=== Etapa 3 em detalhe: análise de frequência por coluna "
            "(melhor tentativa) ==="
        )
        _log_colunas(melhor)

        print("\n=== Melhor resultado encontrado ===")
        print(
            f"Idioma: {melhor.idioma} | Tamanho da chave: {melhor.tamanho_chave} "
            f"| Chave: {melhor.chave} | Score: {melhor.score:.3f}"
        )
        if alertas:
            _log_alertas(alertas)
        print(f"\nTexto decifrado: {melhor.texto}")

    return ResultadoAtaque(
        melhor=melhor,
        tentativas=tentativas,
        alertas=alertas,
        ic_por_tamanho=ic_por_tamanho,
        total_letras=len(cleaned),
    )


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

        print(f"\nOpção inválida. Digite um número entre 1 e {len(chaves)}.\n")


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
