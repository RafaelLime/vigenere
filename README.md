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
| [`vigenere/attack.py`](vigenere/attack.py) | **Parte II.** Primitivas estatísticas: índice de coincidência, análise de frequência, separação em colunas, estimativa do comprimento da chave, qui-quadrado e reconstrução da chave — esta última também na forma que preserva a evidência de cada escolha (`analyze_columns`). Tabelas de frequência PT/EN. |
| [`vigenere/integration.py`](vigenere/integration.py) | **Parte II.** Orquestração do ataque (testa idiomas e comprimentos, avalia o resultado e refina a chave), registro dos resultados intermediários de cada etapa e menu interativo. |
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
resultado.confiavel           # False quando o resultado não é de fiar
resultado.alertas             # os motivos, quando não é
```

Os resultados intermediários de cada etapa também ficam disponíveis, para
inspeção ou para compor o relatório:

```python
resultado.ic_por_tamanho      # IC médio de TODOS os comprimentos examinados
resultado.total_letras        # letras do criptograma normalizado

tentativa = resultado.melhor
tentativa.colunas             # a evidência por posição da chave:
tentativa.colunas[0].length         #   letras nesta coluna
tentativa.colunas[0].frequencies    #   frequências observadas, da maior à menor
tentativa.colunas[0].candidates     #   [(letra, χ²), ...] do melhor ao pior
tentativa.colunas[0].margin         #   folga do vencedor sobre o 2º colocado
tentativa.trocas              # o que o refinamento mudou, e o ganho de score
```

O ataque **sempre** devolve algum resultado — não existe "não encontrei".
Por isso, antes de tomar o texto como resposta, verifique
`resultado.confiavel`. Em modo `verbose` um aviso destacado é impresso
imediatamente antes do texto decifrado quando há motivo para desconfiar.

Passando `idiomas=("pt", "en")` o idioma é **detectado automaticamente**: o
ataque roda para os dois e a tentativa de maior score vence. O menu, por sua
vez, usa apenas o idioma escolhido.

## Metodologia

O ataque segue as etapas pedidas no enunciado. Cada uma **guarda e mostra os
seus resultados intermediários**, não apenas o que passa para a etapa seguinte:
o enunciado (§10) pede que hipóteses testadas e justificativas fiquem visíveis.

**1. Normalização.** O criptograma é reduzido a uma sequência contínua de letras
`A-Z` (`_clean_for_analysis`), porque a análise por colunas fatia o texto por
posição e espaços ou pontuação deslocariam os índices. O IC do criptograma
inteiro já é reportado aqui: se estiver próximo ao da linguagem natural, a chave
tem uma única letra (cifra de César); se estiver próximo ao uniforme, tem mais
de uma.

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

A **tabela completa** (`key_length_scores`) é preservada e impressa, não só os
vencedores: é ela que justifica a escolha, porque nela se vê o IC saltar nos
múltiplos do comprimento real e ficar rente ao valor uniforme em todos os
outros. A barra na saída mede o *excesso* sobre o IC uniforme, e não o IC
absoluto — sem isso a diferença que decide a etapa fica visualmente invisível.

**3. Recuperação da chave — qui-quadrado.** Para cada coluna, testam-se os 26
deslocamentos possíveis. Cada um é comparado com a distribuição de frequências
esperada do idioma pela estatística qui-quadrado:

```
χ² = Σ (observado - esperado)² / esperado
```

O deslocamento de menor χ² é a letra mais provável da chave naquela posição.
As tabelas de frequência de PT e EN estão em
[`attack.py`](vigenere/attack.py), conforme a referência indicada no enunciado.

`analyze_columns` faz essa reconstrução preservando a **evidência de cada
escolha** (`ColumnReport`): quantas letras a coluna tem, as frequências
observadas nela, os candidatos disputados com seus χ² e a *folga* do vencedor
sobre o segundo colocado. A folga é o dado mais informativo do conjunto — uma
folga pequena significa empate técnico, e marca justamente as posições em que a
chave pode estar errada e onde o refinamento da etapa 5 tem chance de agir.

**4. Avaliação do resultado.** O texto decifrado recebe um score que combina
dois sinais independentes: o qui-quadrado do texto inteiro (normalizado) e a
fração de palavras que pertencem a uma lista de palavras comuns do idioma.
Maior score sempre significa mais plausível.

**5. Refinamento.** Quando o score fica abaixo do limiar de aceitação, entra uma
busca local: posição por posição, testam-se as letras alternativas mais
prováveis daquela coluna, mantendo a troca apenas quando ela melhora o score do
texto inteiro. A chave nunca piora — só melhora ou permanece.

**6. Verificação de confiança.** O score ordena candidatos entre si, mas não
diz se o melhor deles é bom. Duas verificações independentes detectam um
resultado sem base estatística:

- **amostra por coluna** — cada coluna é atacada isoladamente contra uma
  distribuição de 26 letras; abaixo de 20 letras por coluna o qui-quadrado
  deixa de medir o idioma e passa a ajustar ruído;
- **IC do texto decifrado** — um IC muito *abaixo* do esperado para o idioma
  indica chave errada (o texto ainda mistura deslocamentos); um IC muito
  *acima* indica superajuste, ou seja, o ataque forçou as colunas a imitar as
  frequências do idioma, o que não ocorre em texto real.

Havendo qualquer um dos dois, o resultado é apresentado com um aviso explícito
de baixa confiança, em vez de ser exibido como se fosse a resposta.

**7. Registro do processo.** Com `verbose=True` as etapas são impressas na
ordem, com os dados que as sustentam: o IC do criptograma, a tabela de IC de
todos os comprimentos com os candidatos marcados, cada tentativa com sua chave e
score, as trocas aceitas pelo refinamento com o ganho de cada uma, e a análise
de frequência posição por posição da tentativa vencedora. Os mesmos dados ficam
no objeto devolvido (`ic_por_tamanho`, `Tentativa.colunas`, `Tentativa.trocas`),
para uso programático ou para compor o relatório.

Os rótulos impressos seguem a numeração desta seção. As etapas 4 a 6 não têm
cabeçalho próprio porque aparecem embutidas: o score na etapa 3, o refinamento
logo abaixo da tentativa que o acionou, e a verificação de confiança junto ao
resultado final. A análise por coluna sai rotulada como *etapa 3 em detalhe*, e
apenas para a tentativa vencedora: as demais já foram justificadas pelo score, e
imprimir todas afogaria a saída.

## Exemplo de execução

Criptograma de 900 letras em formato estrito, chave real `segredo`, atacado como
português com `max_key_length=14`:

```
=== Etapa 1: normalização do criptograma ===
900 letras utilizáveis (A-Z) de 900 caracteres.
IC do criptograma inteiro: 0.0471  (uniforme ≈ 0.0385 | texto claro: pt ≈ 0.0781, en ≈ 0.0655)
  -> IC baixo, próximo ao uniforme: vários deslocamentos foram misturados, ou seja, a chave tem mais de uma letra.

=== Etapa 2: estimativa do tamanho da chave (índice de coincidência) ===
 tam   IC médio   excesso sobre o IC uniforme (≈ 0.0385)
   1     0.0471   ######
   2     0.0467   #####
   3     0.0466   #####
   4     0.0468   ######
   5     0.0468   ######
   6     0.0467   #####
   7     0.0805   ############################  <- candidato testado
   8     0.0462   #####
   9     0.0470   ######
  10     0.0465   #####
  11     0.0471   ######
  12     0.0472   ######
  13     0.0480   ######  <- candidato testado
  14     0.0809   ############################  <- candidato testado

=== Etapa 3: recuperação da chave por idioma e comprimento ===
[pt] tamanho=14 (IC médio das colunas=0.0809) -> chave='SEGREDOSEGREDO' | score=0.886 (tentativa inicial)
[pt] tamanho=7 (IC médio das colunas=0.0805) -> chave='SEGREDO' | score=0.886 (tentativa inicial)
[pt] tamanho=13 (IC médio das colunas=0.0480) -> chave='RRRRRRRDRPPDD' | score=0.288 (tentativa inicial)
[pt] tamanho=13 (IC médio das colunas=0.0480) -> chave='RSRRRRRDRPPDD' | score=0.296 (refinamento)
       posição 2: 'R' -> 'S'  (score 0.288 -> 0.296)

=== Etapa 3 em detalhe: análise de frequência por coluna (melhor tentativa) ===
Chave 'SEGREDOSEGREDO' (pt), posição por posição:
 pos     n  letra        χ²   folga     letras mais frequentes (cifra→claro)     próximos candidatos
   1    65      S     15.14   29.1x     S→A 23.1%  G→O 13.8%  A→I 9.2%           F(441.0) D(566.5)
   2    65      E     26.05    7.1x     W→S 12.3%  H→D 10.8%  I→E 10.8%          P(185.3) D(200.3)
   3    65      G     11.60   37.5x     G→A 18.5%  K→E 13.8%  X→R 9.2%           R(435.2) F(571.3)
   4    65      R     25.75   11.3x     F→O 12.3%  V→E 12.3%  Z→I 10.8%          F(292.2) S(308.0)
   5    64      E     33.62    8.7x     E→A 17.2%  G→C 14.1%  I→E 12.5%          R(291.1) D(295.2)
   6    64      D     26.73   11.9x     L→I 15.6%  H→E 14.1%  U→R 12.5%          R(318.0) Q(364.8)
   7    64      O     38.45    8.0x     O→A 14.1%  Q→C 12.5%  S→E 10.9%          N(308.3) B(322.3)
   8    64      S     40.33   10.7x     A→I 14.1%  J→R 14.1%  K→S 10.9%          F(430.1) T(608.3)
   9    64      E     39.91    7.6x     M→I 18.8%  E→A 12.5%  G→C 12.5%          S(304.7) R(392.3)
  10    64      G     22.48   31.5x     G→A 18.8%  O→I 12.5%  X→R 9.4%           R(707.8) P(740.9)
  11    64      R     40.70    7.4x     R→A 14.1%  T→C 14.1%  Z→I 14.1%          F(301.9) E(376.8)
  12    64      E     16.08   27.6x     E→A 20.3%  I→E 12.5%  W→S 10.9%          P(443.4) D(599.8)
  13    64      D     21.82   10.0x     D→A 18.8%  R→O 15.6%  H→E 10.9%          O(217.7) C(366.9)
  14    64      O     17.39   18.1x     O→A 14.1%  S→E 14.1%  G→S 12.5%          Z(314.4) N(321.7)

=== Melhor resultado encontrado ===
Idioma: pt | Tamanho da chave: 14 | Chave: SEGREDOSEGREDO | Score: 0.886

Texto decifrado: ACRIPTOGRAFIAEAPRATICAEOESTUDODETECNICASPARACOMUNICACAOSEGURANAPRESENCADETERCEIROSADVERSARIOSDEM...
```

Três coisas para observar nessa saída:

- **A etapa 2 justifica a etapa 3.** Só os comprimentos 7 e 14 se destacam; os
  demais ficam todos rente ao IC uniforme. Isso é a evidência de que a chave tem
  7 letras (ou um múltiplo), e não uma afirmação a ser aceita de fora.
- **`SEGREDOSEGREDO` e `SEGREDO` decifram o mesmo texto** e recebem o mesmo
  score; o comprimento 14 foi ranqueado à frente do 7 pelo IC. Ver *Limitações
  conhecidas*, abaixo.
- **O detalhe da etapa 3 mostra por que cada letra foi escolhida.** Na posição 1, a letra
  mais frequente da coluna é `S` (23,1%), que sob a chave `S` decifra como `A` —
  a letra mais comum do português (14,6%). O χ² do vencedor é 29 vezes menor que
  o do segundo colocado, ou seja, a coluna decidiu com folga larga. Onde a folga
  cai abaixo de 1,1x a posição é marcada com `(!)`.

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
  frequentemente falham — mas esses casos agora são **sinalizados** pela
  verificação de confiança, em vez de apresentados como resposta.
- **O score pode preferir uma chave errada à correta.** Em formato estrito o
  único sinal disponível é o qui-quadrado, porque sem espaços o texto decifrado
  é uma única palavra e a fração de palavras comuns é sempre zero. O
  qui-quadrado isolado não basta para discriminar: num caso de teste, uma chave
  com duas letras erradas recebeu score 0,823 contra 0,814 da chave correta.
  A folga por coluna impressa no detalhe da etapa 3 ajuda a detectar isso na
  inspeção: as posições erradas são tipicamente as de folga pequena. Coberto
  pelo teste `test_score_should_prefer_the_correct_key`, marcado como `xfail`.
- **O limiar de aceitação não separa acerto de erro.** `LIMIAR_ACEITACAO = 0,55`
  quase nunca é cruzado em formato estrito: um texto completamente ilegível,
  obtido de um criptograma curto, recebe score entre 0,65 e 0,88. A
  consequência que resta é que o refinamento raramente é acionado — quem
  detecta o resultado ruim é a verificação de confiança da etapa 6, não o
  score. Coberto pelo teste
  `test_illegible_result_should_score_below_the_threshold`, marcado como
  `xfail`.
- **Acentos não são restaurados**, pois a cifra os reduz à letra base (ver
  Parte I).

---

## Executando os testes

A suíte de testes do projeto foi construída utilizando o `pytest`. Os testes cobrem desde a lógica matemática das cifras até a interface de linha de comando e os casos de falha do ataque estatístico.

Para instalar as dependências de teste e executá-los em todo o projeto, utilize:

```bash
pip install -e ".[test]"
pytest
```

Para rodar os testes de um arquivo específico e focar em uma parte do projeto, passe o caminho do arquivo:

```bash
pytest tests/test_integration.py
```

### Cobertura de Testes

| Arquivo | Cobertura |
| --- | --- |
| [`tests/test_cipher.py`](tests/test_cipher.py) | **Parte I:** Cifração, decifração, exemplos canônicos, preservação de maiúsculas/minúsculas, remoção de acentos via NFD e tratamento de caracteres fora do alfabeto A-Z (modos `strict` e `preserve`). |
| [`tests/test_cli.py`](tests/test_cli.py) | **Parte I:** Validação da interface de linha de comando, verificação de leitura/escrita em arquivos (`-i` e `-o`), modo verbose e tratamento de erros (ex: chaves curtas ou textos sem letras). |
| [`tests/test_attack.py`](tests/test_attack.py) | **Parte II:** Primitivas estatísticas. Garante que o Índice de Coincidência para linguagens naturais está próximo do teórico (0.078 PT / 0.065 EN), testa a separação em colunas, a análise de frequência das letras, a tabela completa de IC por comprimento de chave, a análise de Qui-quadrado por coluna, a reconstrução de chaves a partir de fragmentos e a evidência que sustenta cada letra escolhida (`ColumnReport`). |
| [`tests/test_integration.py`](tests/test_integration.py) | **Parte II:** Ataque orquestrado de ponta a ponta. Testa a detecção automática de idioma, a capacidade do IC de achar tamanhos de chave (e seus múltiplos), o refinamento local para melhorar o score de chaves fracas, os gatilhos de segurança (alertas de baixa confiança) e a preservação dos resultados intermediários de cada etapa — tabela de IC, evidência por coluna, trocas do refinamento e os rótulos da saída verbosa. |

### Testes de Limitações Conhecidas (`xfail`)

Os dois defeitos descritos na seção de *Limitações conhecidas* (a preferência ocasional do score por uma chave errada e o limiar de aceitação que falha em textos curtos no modo `strict`) possuem testes na suíte marcados como `xfail` (Expected Fail) no arquivo [`tests/test_integration.py`](tests/test_integration.py). 

Eles descrevem o comportamento **correto** esperado na situação adversa, mas falham de propósito enquanto uma correção matemática melhor não for implementada. Quando o problema for resolvido, os testes reportarão `XPASS` e deverão ser convertidos em asserções normais.
