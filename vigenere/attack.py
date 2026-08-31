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


def estimate_key_length(ciphertext: str, max_length: int = 20) -> int:
    """
    Estima o tamanho provável da chave separando o texto em 
    subconjuntos e buscando a maior média de Índice de Coincidência.
    """
    best_length = 1
    best_ic = 0.0
    
    for k in range(1, max_length + 1):
        # Separa o criptograma em k subconjuntos (fatiamento de listas do Python)
        columns = [ciphertext[i::k] for i in range(k)]
        
        # Calcula a média do IC destas colunas
        avg_ic = sum(calculate_ic(col) for col in columns) / k
        
        # O tamanho de chave que gerar o IC mais alto (mais próximo 
        # do IC de uma linguagem natural) é o provável vencedor
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_length = k
            
    return best_length

def find_key_character(column: str, language_freq: dict = PORTUGUESE_FREQ) -> str:
    """
    Testa os 26 deslocamentos possíveis em uma coluna para encontrar
    a letra da chave que minimiza a estatística Qui-quadrado.
    """
    best_char = 'A'
    lowest_chi_sq = float('inf')
    col_length = len(column)
    
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
                
        # Atualiza a melhor letra da chave se encontrarmos um Qui-quadrado menor
        if chi_sq < lowest_chi_sq:
            lowest_chi_sq = chi_sq
            best_char = chr(shift + ord('A'))
            
    return best_char

def recover_key(ciphertext: str, key_length: int, language_freq: dict = PORTUGUESE_FREQ) -> str:
    """
    Dada uma estimativa do tamanho da chave, separa o criptograma em colunas
    e recupera a chave completa usando as frequências do idioma especificado.
    """
    key = ""
    columns = [ciphertext[i::key_length] for i in range(key_length)]
    
    for col in columns:
        # Repassa o idioma escolhido para a função de Qui-quadrado
        key += find_key_character(col, language_freq)
        
    return key