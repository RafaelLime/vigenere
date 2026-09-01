"""Textos claros usados pelos testes da Parte II.

O índice de coincidência e o qui-quadrado são estimativas estatísticas:
com poucas letras por coluna o ataque deixa de ser confiável. Por isso os
textos aqui são longos.

Não têm acentos, de modo que o texto claro recuperado pelo ataque seja
idêntico ao original — a cifra reduz acentos à letra base e não os
restaura.
"""

PORTUGUESE_TEXT = (
    "A criptografia e a pratica e o estudo de tecnicas para comunicacao segura "
    "na presenca de terceiros adversarios. De modo mais geral a criptografia "
    "trata de construir e analisar protocolos que impedem que terceiros ou o "
    "publico leiam mensagens privadas. A criptografia moderna existe na "
    "intersecao das disciplinas de matematica ciencia da computacao engenharia "
    "eletrica e fisica. As aplicacoes da criptografia incluem o comercio "
    "eletronico os cartoes de pagamento as moedas digitais as senhas de "
    "computador e as comunicacoes militares. "
)

ENGLISH_TEXT = (
    "Cryptography is the practice and study of techniques for secure "
    "communication in the presence of adversarial behavior. More generally "
    "cryptography is about constructing and analyzing protocols that prevent "
    "third parties or the public from reading private messages. Modern "
    "cryptography exists at the intersection of the disciplines of mathematics "
    "computer science electrical engineering and physics. Applications of "
    "cryptography include electronic commerce chip based payment cards digital "
    "currencies computer passwords and military communications. "
)


# Versões longas, usadas nos testes de recuperação. Com o parágrafo
# simples (≈ 470 letras) e chaves de comprimento maior, algumas colunas
# ficam com poucas letras e o qui-quadrado passa a errar letras da chave.
PORTUGUESE_LONG = PORTUGUESE_TEXT * 2
ENGLISH_LONG = ENGLISH_TEXT * 2
