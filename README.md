# Cifra de Vigenère — Implementação e Criptoanálise

Trabalho de Implementação 1 — CIC0201 Segurança Computacional.

Projeto em Python dividido nas duas partes do enunciado:

- **Parte I — Cifrador/decifrador.** A lógica da
  [cifra de Vigenère](https://pt.wikipedia.org/wiki/Cifra_de_Vigen%C3%A8re)
  implementada do zero em [`vigenere/cipher.py`](vigenere/cipher.py), exposta por
  uma interface de linha de comando.
- **Parte II — Ataque de recuperação da chave.** Criptoanálise por índice de
  coincidência e qui-quadrado em [`vigenere/attack.py`](vigenere/attack.py), com o
  ataque automático completo em [`vigenere/integration.py`](vigenere/integration.py).

Nenhuma biblioteca que forneça a cifra pronta ou que realize a criptoanálise
automaticamente é utilizada. Apenas módulos gerais da biblioteca padrão
(`unicodedata`, `collections`, `string`, `argparse`, `dataclasses`).

## Estrutura do projeto

| Arquivo | Conteúdo |
| --- | --- |
| [`vigenere/cipher.py`](vigenere/cipher.py) | **Parte I.** Cifração e decifração. O núcleo matemático está em `_transform`. |
| [`vigenere/cli.py`](vigenere/cli.py) | Interface de linha de comando da Parte I (`encode` / `decode`). |
| [`vigenere/attack.py`](vigenere/attack.py) | **Parte II.** Primitivas estatísticas: índice de coincidência, separação em colunas, estimativa do comprimento da chave, qui-quadrado e reconstrução da chave. Tabelas de frequência PT/EN. |
| [`vigenere/integration.py`](vigenere/integration.py) | **Parte II.** Orquestração do ataque (testa idiomas e comprimentos, avalia o resultado e refina a chave) e menu interativo. |
| [`tests/`](tests/) | Testes automatizados das duas partes. |

## Instalação

```bash
pip install -e .
```

Isso instala o comando `vigenere`. Também é possível executar sem instalar, a
partir da raiz do repositório.

---

# Parte I — Cifrador e Decifrador

## Como funciona

O alfabeto adotado é o clássico, de 26 letras `A-Z`. Cada letra da mensagem é
deslocada pela letra correspondente da chave, que se repete ciclicamente:

```
cifração:   C_i = (P_i + K_i) mod 26
decifração: P_i = (C_i - K_i) mod 26
```

O índice `i` conta apenas as letras da mensagem, de modo que a chave nunca sai
de sincronia com os caracteres em que é aplicada.

### Como cada tipo de caractere é tratado

| Entrada | Tratamento |
| --- | --- |
| `a-z` / `A-Z` | Cifradas. Maiúsculas/minúsculas são preservadas no modo `preserve` e forçadas a maiúsculas no modo `strict`. |
| Letras acentuadas (`á à â ã ç é ê í ó ô õ ú ü ñ …`) | Reduzidas à letra base por decomposição Unicode NFD (`é -> e`, `ç -> c`, `ã -> a`, `Ó -> O`) e então cifradas. **O acento não é restaurado na decifração**: `ação` volta como `acao`. |
| Espaços, dígitos, pontuação | Modo `preserve`: copiados sem alteração e **não** consomem letra da chave. Modo `strict`: descartados. |
| Caracteres da chave | Reduzidos da mesma forma; o que não é letra é ignorado (`l3e!mão` vira `lemao`). Uma chave sem nenhuma letra é erro. |

### Modos de alfabeto

- `--alphabet preserve` (padrão): mantém maiúsculas/minúsculas, espaçamento e
  pontuação, deixando o resultado legível. Em contrapartida, a estrutura do
  texto claro continua visível no criptograma.
- `--alphabet strict`: a saída é uma sequência contínua de letras `A-Z`
  maiúsculas. É o formato usual dos exercícios de criptoanálise e não revela
  os limites das palavras.

```bash
$ vigenere encode "Ataque ao amanhecer!" --key segredo
Sxghyh og esrrksuix!
$ vigenere encode "Ataque ao amanhecer!" --key segredo --alphabet strict
SXGHYHOGESRRKSUIX
```

## Uso

```
vigenere encode [texto] --key CHAVE [--alphabet {preserve,strict}] [-i ARQUIVO] [-o ARQUIVO] [-v]
vigenere decode [texto] --key CHAVE [--alphabet {preserve,strict}] [-i ARQUIVO] [-o ARQUIVO] [-v]
```

Sem instalar: `python -m vigenere encode ...`

| Opção | Significado |
| --- | --- |
| `-k`, `--key` | A chave (obrigatória). |
| `-a`, `--alphabet` | `preserve` (padrão) ou `strict`. |
| `-i`, `--input` | Lê o texto de um arquivo em vez do argumento. |
| `-o`, `--output` | Escreve o resultado em um arquivo em vez da saída padrão. |
| `-v`, `--verbose` | Exibe os parâmetros efetivamente utilizados (em stderr). |

O texto pode ser passado como argumento, com `--input` ou pela entrada padrão
(stdin).

### Exemplos

```bash
$ vigenere encode "ATTACKATDAWN" --key LEMON
LXFOPVEFRNHR

$ vigenere decode "LXFOPVEFRNHR" --key LEMON
ATTACKATDAWN

$ vigenere encode "Olá, você está bem?" --key segredo
Gpg, msfs wwzr fha?

$ echo "Ataque ao amanhecer" | vigenere encode --key segredo
```

Cifrando um arquivo no formato estrito A-Z, com o resumo dos parâmetros:

```bash
$ vigenere encode -i mensagem.txt -o criptograma.txt --key segredo --alphabet strict -v
comando: encode
alfabeto: strict
chave: segredo (tamanho 7)
entrada: 19 caracteres, 17 deles letras
```

### Validação das entradas

O programa recusa uma chave sem nenhuma letra e avisa (em stderr, sem
interromper a execução) quando:

- a chave teve caracteres removidos ou acentos reduzidos, mostrando a chave
  realmente utilizada;
- a chave tem uma única letra, o que a torna equivalente à cifra de César;
- o texto não contém nenhuma letra do alfabeto, de modo que nada foi cifrado.

---

# Parte II — Ataque de Recuperação da Chave

Recupera a chave e o texto claro de um criptograma **sem conhecer a chave**,
explorando as propriedades estatísticas da linguagem natural.

## Como executar

O ataque é acessível pelo menu interativo:

```bash
python -m vigenere.integration
```

O menu pergunta primeiro o idioma do texto, depois a operação, e então pede o
criptograma:

```
=== Cifra de Vigenère ===

Selecione o idioma do texto:
  1. Português
  2. Inglês
> 1

Selecione a operação:
  1. Cifrar um texto (chave conhecida)
  2. Decifrar um texto (chave conhecida)
  3. Atacar um criptograma (chave desconhecida - criptoanálise)
> 3

Digite o criptograma a ser atacado: SGXZTWCYVGWMDSSTXRXLQSIU...
```

Também pode ser usado como biblioteca, com controle sobre os parâmetros:

```python
from vigenere.integration import resolver_criptograma

resultado = resolver_criptograma(
    criptograma,
    idiomas=("pt", "en"),        # testa os dois e escolhe o mais plausível
    max_key_length=20,           # maior comprimento de chave considerado
    n_tamanhos_candidatos=3,     # quantos comprimentos candidatos testar
    verbose=True,                # imprime o processo de busca
)

resultado.melhor.chave        # chave recuperada
resultado.melhor.texto        # texto claro
resultado.melhor.score        # plausibilidade (maior = melhor)
resultado.tentativas          # histórico de todas as tentativas
```

Passando `idiomas=("pt", "en")` o idioma é **detectado automaticamente**: o
ataque roda para os dois e a tentativa de maior score vence. O menu, por sua
vez, usa apenas o idioma escolhido.

## Metodologia

O ataque segue as etapas pedidas no enunciado:

**1. Normalização.** O criptograma é reduzido a uma sequência contínua de letras
`A-Z` (`_clean_for_analysis`), porque a análise por colunas fatia o texto por
posição e espaços ou pontuação deslocariam os índices.

**2. Estimativa do comprimento da chave — índice de coincidência.** Para cada
comprimento `k` de 1 a `max_key_length`, o texto é separado em `k` colunas e
calcula-se o IC médio das colunas:

```
IC = Σ n_i(n_i - 1) / N(N - 1)
```

Cada coluna de um Vigenère com chave de comprimento `k` foi cifrada por um único
deslocamento — ou seja, é uma cifra de César, e preserva o IC da linguagem
natural — pelas tabelas de frequência usadas aqui, ≈ 0,078 para o português e
≈ 0,065 para o inglês. Comprimentos errados misturam deslocamentos diferentes e
o IC cai para ≈ 0,038, o de uma distribuição uniforme (1/26). Em vez de aceitar
apenas o melhor `k`, o ataque guarda os `n_tamanhos_candidatos` melhores e testa
todos.

**3. Recuperação da chave — qui-quadrado.** Para cada coluna, testam-se os 26
deslocamentos possíveis. Cada um é comparado com a distribuição de frequências
esperada do idioma pela estatística qui-quadrado:

```
χ² = Σ (observado - esperado)² / esperado
```

O deslocamento de menor χ² é a letra mais provável da chave naquela posição.
As tabelas de frequência de PT e EN estão em
[`attack.py`](vigenere/attack.py), conforme a referência indicada no enunciado.

**4. Avaliação do resultado.** O texto decifrado recebe um score que combina
dois sinais independentes: o qui-quadrado do texto inteiro (normalizado) e a
fração de palavras que pertencem a uma lista de palavras comuns do idioma.
Maior score sempre significa mais plausível.

**5. Refinamento.** Quando o score fica abaixo do limiar de aceitação, entra uma
busca local: posição por posição, testam-se as letras alternativas mais
prováveis daquela coluna, mantendo a troca apenas quando ela melhora o score do
texto inteiro. A chave nunca piora — só melhora ou permanece.

**6. Registro do processo.** Com `verbose=True` cada tentativa é impressa, de
modo que o caminho percorrido fique visível, e não apenas a resposta final.

## Exemplo de execução

Criptograma de 616 letras, chave real `segredo`, atacado como português:

```
[pt] tamanho=14 (IC médio das colunas=0.0979) -> chave='SEGREDOSEGREDO' | score=0.870 (tentativa inicial)
[pt] tamanho=7  (IC médio das colunas=0.0852) -> chave='SEGREDO'        | score=0.870 (tentativa inicial)
[pt] tamanho=11 (IC médio das colunas=0.0652) -> chave='REFRGRREDDC'    | score=0.341 (tentativa inicial)
[pt] tamanho=11 (IC médio das colunas=0.0652) -> chave='eEelGsREDDC'    | score=0.367 (refinamento)

=== Melhor resultado encontrado ===
Idioma: pt | Tamanho da chave: 14 | Chave: SEGREDOSEGREDO | Score: 0.870

Texto decifrado: ACRIPTOGRAFIAEAPRATICAEOESTUDODETECNICASPARACOMUNICACAO...
```

Observe o efeito descrito na próxima seção: `SEGREDOSEGREDO` e `SEGREDO`
decifram exatamente o mesmo texto e recebem o mesmo score, e o comprimento 14
foi ranqueado à frente do 7 pelo IC.

## Limitações conhecidas

- **O comprimento estimado pode ser um múltiplo do real.** Qualquer múltiplo do
  comprimento verdadeiro também separa o texto em colunas de César válidas, e
  portanto também apresenta IC alto. Como colunas mais curtas produzem IC mais
  ruidoso, um múltiplo às vezes é ranqueado à frente do comprimento real. A
  chave resultante (`SEGREDOSEGREDO`) é equivalente à real (`SEGREDO`) e
  recupera o texto claro corretamente, mas o comprimento reportado fica
  superestimado.
- **Chaves mais longas que `max_key_length` (padrão 20) não são encontradas.**
  Nesse caso o resultado apresentado é ilegível. Aumente `max_key_length` se
  houver suspeita de chave longa.
- **Criptogramas curtos são pouco confiáveis.** O IC e o qui-quadrado são
  estimativas estatísticas: quanto mais curto o texto (e quanto maior a chave),
  menos letras por coluna e mais ruído. Nos testes, textos abaixo de ~200 letras
  frequentemente falham.
- **O score pode preferir uma chave errada à correta.** Em formato estrito o
  único sinal disponível é o qui-quadrado, porque sem espaços o texto decifrado
  é uma única palavra e a fração de palavras comuns é sempre zero. O
  qui-quadrado isolado não basta para discriminar: num caso de teste, uma chave
  com duas letras erradas recebeu score 0,823 contra 0,814 da chave correta.
  Coberto pelo teste `test_score_should_prefer_the_correct_key`, marcado como
  `xfail`.
- **O limiar de aceitação não separa acerto de erro.** `LIMIAR_ACEITACAO = 0,55`
  quase nunca é cruzado em formato estrito: um texto completamente ilegível,
  obtido de um criptograma curto, recebe score entre 0,65 e 0,88. Como
  consequência, o refinamento raramente é acionado e o programa **sempre**
  apresenta a melhor tentativa sem nenhum aviso de baixa confiança, mesmo
  quando nenhuma é boa. Coberto pelo teste
  `test_illegible_result_should_score_below_the_threshold`, marcado como
  `xfail`.
- **Acentos não são restaurados**, pois a cifra os reduz à letra base (ver
  Parte I).

---

## Executando os testes

```bash
pip install -e ".[test]"
pytest
```

| Arquivo | Cobertura |
| --- | --- |
| [`tests/test_cipher.py`](tests/test_cipher.py) | Parte I: cifração, decifração, tratamento do alfabeto e dos acentos. |
| [`tests/test_cli.py`](tests/test_cli.py) | Parte I: interface de linha de comando e validação das entradas. |
| [`tests/test_attack.py`](tests/test_attack.py) | Parte II: índice de coincidência, separação em colunas, estimativa do comprimento, qui-quadrado e reconstrução da chave. |
| [`tests/test_integration.py`](tests/test_integration.py) | Parte II: ataque de ponta a ponta em PT e EN, detecção de idioma, refinamento, histórico de tentativas e limites conhecidos. |

Os dois defeitos descritos em *Limitações conhecidas* têm testes marcados como
`xfail`: eles descrevem o comportamento **correto** e falham de propósito
enquanto a correção não entra. Quando entrar, viram `XPASS` e devem ser
convertidos em asserções normais.
