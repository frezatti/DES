# DES (Data Encryption Standard) em C

Implementação didática do cifrador de bloco DES (64 bits) em C, incluindo:
- Criptografia e descriptografia de bloco único (64 bits)
- Agendamento de chave (PC-1, rotações por rodada, PC-2)
- Utilitários de bytes big-endian para E/S de blocos
- CLI interativo:
  - Chave: aleatória, hexadecimal, ou string (≤ 8 chars)
  - Texto de qualquer tamanho
  - Padding simples com zeros até múltiplos de 8
  - Cifra em Base64 para facilitar a cópia/cola

Aviso: DES e ECB com padding simples não são seguros para produção. Este projeto tem fins educacionais.

---

## Sumário

- Visão geral
- Estrutura do projeto
- Pré-requisitos
- Compilação
- Uso
- Exemplos
- Detalhes de implementação
- Limitações
- Testes sugeridos
- Licença

---

## Visão geral

O DES cifra blocos de 64 bits usando uma chave de 64 bits (56 bits efetivos + 8 bits de paridade). Esta implementação:
- Usa tabelas oficiais do DES para as permutações e S-boxes
- Implementa o agendamento de chaves conforme o padrão (PC-1, rotações, PC-2)
- Fornece helpers para operar em buffers arbitrários com padding zero

A CLI permite:
- Escolher ação: criptografar, descriptografar ou ambos
- Escolher a forma de entrada da chave
- Trabalhar com texto arbitrário; o resultado cifrado é exibido em Base64

---

## Estrutura do projeto

- des.h
  - API pública (des_encrypt_block, des_decrypt_block, des_key_schedule)
  - Helpers de buffer: des_encrypt_buffer_zeropad, des_decrypt_buffer_nopad

- des.c
  - Implementação do DES: IP, 16 rodadas (função f), IP^-1
  - Agendamento de chaves (PC-1, rotações, PC-2)
  - Buffer helpers com padding zero

- des_tables.h / des_tables.c
  - Tabelas oficiais: IP, IP^-1, E, P, PC-1, PC-2, rotações e S-boxes S1..S8

- des_bytes.h
  - Helpers inline big-endian:
    - load_be64: bytes[8] -> uint64_t
    - store_be64: uint64_t -> bytes[8]

- main.c
  - CLI interativo: entrada de chave, criptografia/decriptografia
  - Base64 para exibir/receber a cifra

- Makefile
  - Build com gcc

---

## Pré-requisitos

- gcc ou clang
- make
- Unix/Linux recomendado
  - O main usa /dev/urandom para chave aleatória

---

## Compilação

Usando Make:
- make
- Executável gerado: ./des_test

Sem Make:
- gcc -std=c11 -O2 -Wall -Wextra -c des_tables.c
- gcc -std=c11 -O2 -Wall -Wextra -c des.c
- gcc -std=c11 -O2 -Wall -Wextra -c main.c
- gcc -std=c11 -O2 -Wall -Wextra -o des_test main.o des.o des_tables.o

Makefile (resumo):
- Gera des_test a partir de des.c, des_tables.c e main.c
- clean remove objetos e binário

---

## Uso

1) Execute:
- ./des_test

2) Escolha a ação:
- e = criptografar
- d = descriptografar
- b = ambos

3) Informe a chave:
- r = aleatória (64 bits)
- h = hexadecimal (16 dígitos, ex.: 133457799BBCDFF1)
- s = string ASCII (≤ 8 chars; será zero-padded)

4) Criptografia:
- Digite uma linha de texto
- O programa faz padding com zeros até múltiplo de 8
- Exibe a cifra em Base64

5) Descriptografia:
- Informe a cifra em Base64
- O comprimento decodificado deve ser múltiplo de 8
- O programa imprime os bytes de plaintext (zeros finais podem aparecer por conta do padding)

---

## Exemplos

Criptografar com chave aleatória:
- Ação: e
- Chave: r
- Texto: Ola mundo!
- Saída: Ciphertext (Base64): AbCdEfGh... (exemplo)

Descriptografar:
- Ação: d
- Chave: use a mesma do passo anterior
- Cole o Base64 gerado
- Saída: Decrypted (N bytes): Ola mundo! (seguido de possíveis zeros invisíveis)

Usando chave hex e vetor de teste clássico NIST:
- Chave (hex): 133457799BBCDFF1
- Texto (hex, para teste de bloco único): 0123456789ABCDEF
- Resultado esperado (cifra hex): 85E813540F0AB405
- Dica: para este teste específico, use um main de bloco único ou adapte para aceitar hex no plaintext

---

## Detalhes de implementação

- Blocos e endianness:
  - DES opera em blocos de 64 bits
  - load_be64/store_be64 garantem ordem de bytes consistente (big-endian)

- Rodadas do DES:
  - IP → 16 rodadas Feistel → IP^-1
  - Em cada rodada: R é expandido para 48 bits (E), XOR com a subchave K_i, S-boxes (8×6 → 8×4 = 32 bits), permutação P; L e R são trocados conforme Feistel

- Agendamento de chaves:
  - PC-1: 64 → 56 bits (descarta paridade)
  - Separa em C e D (28 bits)
  - Rotaciona C e D à esquerda segundo a tabela por rodada
  - PC-2: 56 → 48 bits gera K1..K16

- Buffer helpers:
  - des_encrypt_buffer_zeropad:
    - Se o tamanho não é múltiplo de 8, completa com zeros até o próximo múltiplo
    - Retorna novo buffer e tamanho
  - des_decrypt_buffer_nopad:
    - Requer comprimento múltiplo de 8
    - Não remove zeros do final (caller decide)

- Base64:
  - Para terminal: evita bytes não imprimíveis
  - Decodificação valida e exige que o resultado seja múltiplo de 8 para decriptar

---

## Limitações

- Segurança:
  - DES (56 bits efetivos) está obsoleto
  - Modo ECB e padding zero são inseguros para dados reais
- Ambiguidade do padding zero:
  - Zeros finais do plaintext são indistinguíveis do padding após decriptar
- Paridade da chave:
  - Não forçamos paridade ímpar por byte; PC-1 descarta esses bits
- Vetores de teste hex no CLI:
  - O main atual trabalha com texto e Base64; para testes hex de bloco único, use um utilitário separado ou adapte a CLI

---

## Testes sugeridos

- Vetor NIST (bloco único):
  - Chave: 0x133457799BBCDFF1
  - Texto: 0x0123456789ABCDEF
  - Cifra: 0x85E813540F0AB405
- Propriedade de ida-e-volta:
  - Para várias chaves e mensagens, verifique se D(E(M)) == M
  - Lembre: zeros do padding podem aparecer no fim do plaintext

---

## Licença

Uso livre para fins acadêmicos e pessoais.

---

## Próximos passos (opcional)

- Suporte a CBC com IV aleatório (Base64 em IV||C)
- Padding PKCS#7 para remover ambiguidade na decriptação
- Vetor de testes NIST integrado ao CLI (modo “hex” para plaintext)
- Otimizações de permutação (bit hacks) e tabelas de lookup

Em caso de dúvidas ou para estender com CBC/PKCS#7, peça orientações.
