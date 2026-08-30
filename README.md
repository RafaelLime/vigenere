# Cifra de Vigenère

Projeto em Python que cifra e decifra textos com a
[cifra de Vigenère](https://pt.wikipedia.org/wiki/Cifra_de_Vigen%C3%A8re),
disponibilizado por uma interface de linha de comando. A lógica da cifra foi
implementada do zero em [`vigenere/cipher.py`](vigenere/cipher.py); nenhuma
biblioteca de criptografia é utilizada.

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

## Instalação

```bash
pip install -e .
```

Isso instala o comando `vigenere`. Também é possível executar sem instalar,
com `python -m vigenere`.

## Uso

```
vigenere encode [texto] --key CHAVE [--alphabet {preserve,strict}] [-i ARQUIVO] [-o ARQUIVO] [-v]
vigenere decode [texto] --key CHAVE [--alphabet {preserve,strict}] [-i ARQUIVO] [-o ARQUIVO] [-v]
```

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

## Executando os testes

```bash
pip install -e ".[test]"
pytest
```
