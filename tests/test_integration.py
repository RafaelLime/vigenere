"""Testes do ataque automático completo (Parte II)."""

import pytest

from vigenere.cipher import decode, encode
from vigenere.integration import (
    LIMIAR_ACEITACAO,
    MIN_LETRAS_POR_COLUNA,
    ResultadoAtaque,
    Tentativa,
    _clean_for_analysis,
    _common_word_ratio,
    _ic_esperado,
    _score_candidate,
    resolver_criptograma,
)

from textos import (
    ENGLISH_LONG,
    ENGLISH_TEXT,
    PORTUGUESE_LONG,
    PORTUGUESE_TEXT,
)


def _menor_periodo(chave):
    """Devolve o menor bloco cuja repetição gera ``chave``.

    O ataque pode reportar um múltiplo do comprimento real da chave
    ('SEGREDOSEGREDO' em vez de 'SEGREDO'), porque múltiplos também
    separam o texto em colunas de César válidas. As duas chaves são
    equivalentes: decifram exatamente o mesmo texto.
    """
    for tamanho in range(1, len(chave) + 1):
        if len(chave) % tamanho == 0:
            bloco = chave[:tamanho]
            if bloco * (len(chave) // tamanho) == chave:
                return bloco
    return chave


def _normalizado(text, alphabet="strict"):
    """O texto claro como o ataque o devolve (chave 'a' = deslocamento zero)."""
    return encode(text, "a", alphabet=alphabet)


# --- Normalização ------------------------------------------------------------


def test_clean_for_analysis_keeps_only_uppercase_letters():
    assert _clean_for_analysis("Olá, você está bem?") == "OLAVOCEESTABEM"


def test_clean_for_analysis_does_not_shift_the_letters():
    # É apenas normalização, não cifração: as letras não podem mudar.
    assert _clean_for_analysis("ATTACK AT DAWN!") == "ATTACKATDAWN"


# --- Avaliação do texto decifrado --------------------------------------------


def test_real_text_scores_higher_than_scrambled_text():
    lixo = encode(PORTUGUESE_TEXT, "chavequalquer")
    assert _score_candidate(PORTUGUESE_TEXT, "pt") > _score_candidate(lixo, "pt")


@pytest.mark.parametrize(
    "text, idioma, outro",
    [(PORTUGUESE_TEXT, "pt", "en"), (ENGLISH_TEXT, "en", "pt")],
    ids=["pt", "en"],
)
def test_text_scores_higher_against_its_own_language(text, idioma, outro):
    assert _score_candidate(text, idioma) > _score_candidate(text, outro)


def test_common_word_ratio_is_higher_for_the_matching_language():
    assert _common_word_ratio(PORTUGUESE_TEXT, "pt") > _common_word_ratio(
        PORTUGUESE_TEXT, "en"
    )
    assert _common_word_ratio(ENGLISH_TEXT, "en") > _common_word_ratio(
        ENGLISH_TEXT, "pt"
    )


def test_common_word_ratio_of_text_without_words_is_zero():
    assert _common_word_ratio("", "pt") == 0.0
    assert _common_word_ratio("123 !!! ...", "pt") == 0.0


def test_common_word_ratio_is_useless_without_word_boundaries():
    # Num criptograma no formato estrito (letras contínuas, sem espaços)
    # o texto decifrado é uma única "palavra": o sinal lexical desaparece
    # e o score passa a depender apenas do qui-quadrado.
    assert _common_word_ratio(_normalizado(PORTUGUESE_TEXT), "pt") == 0.0


# --- Ataque ponta a ponta ----------------------------------------------------


@pytest.mark.parametrize(
    "text, idioma, key",
    [
        (PORTUGUESE_LONG, "pt", "segredo"),
        (PORTUGUESE_LONG, "pt", "ab"),
        (PORTUGUESE_LONG, "pt", "chaveextensa"),
        (ENGLISH_LONG, "en", "lemon"),
        (ENGLISH_LONG, "en", "cryptokey"),
    ],
    ids=["pt-segredo", "pt-ab", "pt-chaveextensa", "en-lemon", "en-cryptokey"],
)
@pytest.mark.parametrize("alphabet", ["strict", "preserve"])
def test_attack_recovers_the_plaintext(text, idioma, key, alphabet):
    criptograma = encode(text, key, alphabet=alphabet)
    resultado = resolver_criptograma(
        criptograma, idiomas=(idioma,), verbose=False
    )

    assert resultado.melhor.texto == _normalizado(text, alphabet)


@pytest.mark.parametrize(
    "text, idioma, key",
    [(PORTUGUESE_LONG, "pt", "segredo"), (ENGLISH_LONG, "en", "lemon")],
    ids=["pt", "en"],
)
def test_attack_recovers_a_key_equivalent_to_the_real_one(text, idioma, key):
    criptograma = encode(text, key, alphabet="strict")
    resultado = resolver_criptograma(
        criptograma, idiomas=(idioma,), verbose=False
    )

    # A chave pode vir repetida (um múltiplo do comprimento real), mas o
    # seu menor período tem de ser a chave verdadeira.
    assert _menor_periodo(resultado.melhor.chave.lower()) == key
    # E precisa realmente decifrar o criptograma.
    assert decode(criptograma, resultado.melhor.chave) == _normalizado(text)


@pytest.mark.parametrize(
    "text, esperado, key",
    [(PORTUGUESE_LONG, "pt", "segredo"), (ENGLISH_LONG, "en", "lemon")],
    ids=["pt", "en"],
)
def test_attack_detects_the_language_on_its_own(text, esperado, key):
    # Com os dois idiomas habilitados, o ataque roda para ambos e a
    # tentativa de maior score vence.
    criptograma = encode(text, key, alphabet="strict")
    resultado = resolver_criptograma(
        criptograma, idiomas=("pt", "en"), verbose=False
    )

    assert resultado.melhor.idioma == esperado
    assert resultado.melhor.texto == _normalizado(text)


def test_attack_succeeds_without_knowing_the_key_length():
    # O comprimento nunca é informado: é estimado pelo índice de
    # coincidência.
    criptograma = encode(PORTUGUESE_LONG, "umachavelonga", alphabet="strict")
    resultado = resolver_criptograma(criptograma, idiomas=("pt",), verbose=False)

    assert _menor_periodo(resultado.melhor.chave.lower()) == "umachavelonga"


# --- Histórico e estrutura do resultado --------------------------------------


def test_result_records_every_attempt_and_the_best_is_among_them():
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resultado = resolver_criptograma(
        criptograma, idiomas=("pt", "en"), n_tamanhos_candidatos=3, verbose=False
    )

    assert isinstance(resultado, ResultadoAtaque)
    # Dois idiomas × três comprimentos candidatos, mais os refinamentos.
    assert len(resultado.tentativas) >= 6
    assert all(isinstance(t, Tentativa) for t in resultado.tentativas)
    assert resultado.melhor in resultado.tentativas
    # A melhor é, de fato, a de maior score.
    assert resultado.melhor.score == max(t.score for t in resultado.tentativas)


def test_n_tamanhos_candidatos_controls_how_many_lengths_are_tried():
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resultado = resolver_criptograma(
        criptograma, idiomas=("pt",), n_tamanhos_candidatos=2, verbose=False
    )

    iniciais = [t for t in resultado.tentativas if not t.refinada]
    assert len(iniciais) == 2


def test_weak_attempts_trigger_a_refinement_pass():
    # Entre os comprimentos candidatos há sempre algum errado (aqui 13,
    # que não é múltiplo de 7): ele produz um texto ruim, cujo score fica
    # abaixo do limiar e aciona o refinamento pedido no enunciado.
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resultado = resolver_criptograma(criptograma, idiomas=("pt",), verbose=False)

    assert any(t.refinada for t in resultado.tentativas)


def test_refinement_never_lowers_the_score():
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resultado = resolver_criptograma(criptograma, idiomas=("pt",), verbose=False)

    # Cada refinamento parte de uma tentativa inicial de mesmo idioma e
    # comprimento; a busca local só aceita trocas que melhoram o score.
    refinadas = [t for t in resultado.tentativas if t.refinada]
    assert refinadas  # o caso escolhido garante ao menos um refinamento
    for refinada in refinadas:
        inicial = next(
            t
            for t in resultado.tentativas
            if not t.refinada
            and t.idioma == refinada.idioma
            and t.tamanho_chave == refinada.tamanho_chave
        )
        assert refinada.score >= inicial.score


def test_only_attempts_below_the_threshold_are_refined():
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resultado = resolver_criptograma(criptograma, idiomas=("pt",), verbose=False)

    refinadas = {
        (t.idioma, t.tamanho_chave) for t in resultado.tentativas if t.refinada
    }
    for tentativa in resultado.tentativas:
        if tentativa.refinada:
            continue
        abaixo = tentativa.score < LIMIAR_ACEITACAO
        assert abaixo == ((tentativa.idioma, tentativa.tamanho_chave) in refinadas)


def test_verbose_prints_the_search_path(capsys):
    # O enunciado pede que o processo fique visível, não só a resposta.
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resolver_criptograma(criptograma, idiomas=("pt",), verbose=True)

    saida = capsys.readouterr().out
    assert "Melhor resultado encontrado" in saida
    assert "IC médio das colunas" in saida
    assert "tentativa inicial" in saida
    assert "refinamento" in saida


def test_quiet_mode_prints_nothing(capsys):
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resolver_criptograma(criptograma, idiomas=("pt",), verbose=False)

    assert capsys.readouterr().out == ""


# --- Parâmetros e limites ----------------------------------------------------


def test_max_key_length_bounds_the_search():
    resultado = resolver_criptograma(
        encode(PORTUGUESE_LONG, "segredo", alphabet="strict"),
        idiomas=("pt",),
        max_key_length=8,
        verbose=False,
    )
    assert all(t.tamanho_chave <= 8 for t in resultado.tentativas)


def test_a_key_longer_than_max_key_length_is_not_found():
    # Limitação conhecida e documentada: uma chave acima do limite de
    # busca não é encontrada, e o resultado apresentado é ilegível.
    chave = "chavemuitolongaparaobuscapadrao"  # 31 letras
    criptograma = encode(PORTUGUESE_LONG, chave, alphabet="strict")
    resultado = resolver_criptograma(
        criptograma, idiomas=("pt",), max_key_length=20, verbose=False
    )

    assert _menor_periodo(resultado.melhor.chave.lower()) != chave
    assert resultado.melhor.texto != _normalizado(PORTUGUESE_LONG)


# --- Avaliação da confiança do resultado -------------------------------------


def test_ic_esperado_matches_the_frequency_tables():
    # IC teórico = soma dos quadrados das frequências das letras.
    assert _ic_esperado("pt") == pytest.approx(0.078, abs=0.002)
    assert _ic_esperado("en") == pytest.approx(0.065, abs=0.002)


@pytest.mark.parametrize(
    "text, idioma, key",
    [(PORTUGUESE_LONG, "pt", "segredo"), (ENGLISH_LONG, "en", "lemon")],
    ids=["pt", "en"],
)
def test_a_successful_attack_reports_no_warnings(text, idioma, key):
    criptograma = encode(text, key, alphabet="strict")
    resultado = resolver_criptograma(
        criptograma, idiomas=(idioma,), verbose=False
    )

    assert resultado.melhor.texto == _normalizado(text)
    assert resultado.alertas == []
    assert resultado.confiavel


@pytest.mark.parametrize("n", [40, 60, 80])
def test_a_short_cryptogram_is_flagged_as_unreliable(n):
    # Poucas letras por coluna: a análise de frequência superajusta e
    # produz um texto que imita as frequências do idioma sem ser
    # linguagem real. O resultado não pode ser apresentado como sucesso.
    claro = _normalizado(PORTUGUESE_LONG)[:n]
    resultado = resolver_criptograma(
        encode(claro, "segredo", alphabet="strict"), idiomas=("pt",), verbose=False
    )

    assert resultado.melhor.texto != claro  # de fato falhou
    assert not resultado.confiavel  # e o programa avisa
    assert resultado.alertas


def test_a_key_longer_than_the_search_limit_is_flagged():
    criptograma = encode(
        PORTUGUESE_LONG, "chavemuitolongaparaobuscapadrao", alphabet="strict"
    )
    resultado = resolver_criptograma(
        criptograma, idiomas=("pt",), max_key_length=20, verbose=False
    )

    assert resultado.melhor.texto != _normalizado(PORTUGUESE_LONG)
    assert not resultado.confiavel
    # A chave errada deixa o texto misturando deslocamentos, e o IC cai.
    assert any("abaixo do esperado" in a for a in resultado.alertas)


def test_insufficient_sample_is_reported_with_the_column_size():
    criptograma = encode("Ataque ao amanhecer", "segredo", alphabet="strict")
    resultado = resolver_criptograma(criptograma, idiomas=("pt",), verbose=False)

    assert any("letras por coluna" in a for a in resultado.alertas)
    assert any(str(MIN_LETRAS_POR_COLUNA) in a for a in resultado.alertas)


def test_overfitted_columns_are_reported():
    # Com colunas muito curtas o ataque força as frequências e o IC do
    # texto decifrado sobe acima do natural — sinal de superajuste.
    claro = _normalizado(PORTUGUESE_LONG)[:40]
    resultado = resolver_criptograma(
        encode(claro, "segredo", alphabet="strict"), idiomas=("pt",), verbose=False
    )

    assert any("acima do esperado" in a for a in resultado.alertas)


def test_warning_is_printed_before_the_plaintext(capsys):
    criptograma = encode("Ataque ao amanhecer", "segredo", alphabet="strict")
    resolver_criptograma(criptograma, idiomas=("pt",), verbose=True)

    saida = capsys.readouterr().out
    assert "ATENÇÃO: resultado de baixa confiança" in saida
    assert "provavelmente NÃO é o texto claro correto" in saida
    # O aviso precisa vir antes do texto, ou passa desapercebido.
    assert saida.index("ATENÇÃO") < saida.index("Texto decifrado")


def test_no_warning_is_printed_for_a_good_result(capsys):
    criptograma = encode(PORTUGUESE_LONG, "segredo", alphabet="strict")
    resolver_criptograma(criptograma, idiomas=("pt",), verbose=True)

    assert "ATENÇÃO" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "entrada",
    ["", "   ", "!!! ... 123", "X", "XY"],
    ids=["vazio", "espacos", "sem-letras", "uma-letra", "duas-letras"],
)
def test_degenerate_input_does_not_crash_and_is_flagged(entrada):
    # O menu aceita texto livre: entrada degenerada não pode quebrar o
    # ataque, e nunca deve ser apresentada como um resultado válido.
    resultado = resolver_criptograma(entrada, idiomas=("pt",), verbose=False)

    assert not resultado.confiavel
    assert resultado.alertas


# --- Limitações conhecidas ---------------------------------------------------
#
# Os dois testes abaixo documentam defeitos reais, ainda não corrigidos.
# Estão marcados como xfail: quando a correção entrar, viram XPASS e
# devem ser convertidos em asserções normais.


@pytest.mark.xfail(
    reason=(
        "O score pode preferir uma chave errada à correta. Com o parágrafo "
        "simples em inglês e a chave 'lemon', o comprimento candidato 20 "
        "produz 'LPMONLEMONLEMYNLEMON' (duas letras erradas) e recebe score "
        "0,823, acima do 0,814 da chave correta 'LEMON'. Em formato estrito "
        "o único sinal é o qui-quadrado, e ele não basta para discriminar."
    ),
    strict=True,
)
def test_score_should_prefer_the_correct_key():
    criptograma = encode(ENGLISH_TEXT, "lemon", alphabet="strict")
    resultado = resolver_criptograma(criptograma, idiomas=("en",), verbose=False)

    assert resultado.melhor.texto == _normalizado(ENGLISH_TEXT)


@pytest.mark.xfail(
    reason=(
        "LIMIAR_ACEITACAO=0,55 não separa acerto de erro em formato "
        "estrito: um texto completamente ilegível obtido de um criptograma "
        "curto recebe score 0,65–0,88, acima do limiar. O score continua "
        "servindo apenas para ordenar candidatos entre si; quem detecta o "
        "resultado ruim é a avaliação de confiança (ResultadoAtaque.alertas), "
        "testada acima."
    ),
    strict=True,
)
def test_illegible_result_should_score_below_the_threshold():
    criptograma = encode(PORTUGUESE_TEXT[:80], "segredo", alphabet="strict")
    resultado = resolver_criptograma(criptograma, idiomas=("pt",), verbose=False)

    # O texto recuperado é lixo, então o score deveria sinalizar isso.
    assert resultado.melhor.texto != _normalizado(PORTUGUESE_TEXT[:80])
    assert resultado.melhor.score < LIMIAR_ACEITACAO
