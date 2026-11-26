# Relatório Técnico — Etapa 1

## 7.1 Identificação

| Campo       | Segurança da Informação                                                                       |
| ----------- | -------------------------------------------------------------------------------- |
| Integrantes | Ester Marina, Gabriel Trindade, Lorena Alice                                     |
| Turma       | 5                                                                                |
| Linguagem   | Python 3.12 (compatível com 3.9+)                                                |
| Repositório | _(https://github.com/gbieltrindade/Trabalho-Criptografica)_ — tag `v1.0-entrega` |

## 7.2 Descrição da Solução

**Bibliotecas.** `cryptography` (PyCA, mantida e amplamente auditada) para Ed25519, serialização PEM
e exceções de verificação; `hashlib` (biblioteca padrão) para SHA-256; `hmac.compare_digest` para
comparação de hashes em tempo constante; `argparse` para a CLI; `unittest` para os testes.

**Organização.** Um único módulo, `src/seguranca.py`, dividido em: (i) utilitários de E/S binária,
(ii) operações criptográficas (`sha256_arquivo`, `carregar_chave_*`), (iii) um `cmd_*` por comando e
(iv) `main()`, que converte erros em mensagens claras e códigos de saída. Testes em
`tests/test_seguranca.py` executam a CLI como processo externo.

**Principais decisões técnicas.**

- Ed25519 aplicado **diretamente aos bytes** do arquivo (sem pré-hash), como exige o contrato.
- Leitura estritamente binária; o hash é calculado em blocos de 1 MiB (suporta arquivos grandes).
- Chaves: privada em PKCS#8 sem senha, pública em SubjectPublicKeyInfo; `.sig` com exatamente 64 bytes.
- Códigos de saída: `0` sucesso; `1` verificação falhou; `2` erro. Qualquer exceção inesperada vira
  código `2`, de modo que uma falha nunca seja apresentada como válida.
- Segurança operacional: chave privada criada com permissão `0600` (POSIX), sem sobrescrever arquivos
  existentes sem `--force`, e validação do tipo da chave (rejeita RSA/EC e chave pública no lugar da privada).
- Assinatura com tamanho diferente de 64 bytes é tratada como **inválida** (código 1).

## 7.3 Funcionalidades Implementadas

| Req. | Descrição                                  | Comando  | Status                                                              |
| ---- | ------------------------------------------ | -------- | ------------------------------------------------------------------- |
| R01  | Gerar par de chaves Ed25519                | `keygen` | Atendido                                                            |
| R02  | Calcular SHA-256                           | `hash`   | Atendido                                                            |
| R03  | Comparar hash com referência               | `check`  | Atendido (aceita referência em maiúsculas/minúsculas; exige 64 hex) |
| R04  | Assinar arquivo com chave privada          | `sign`   | Atendido                                                            |
| R05  | Verificar assinatura com chave pública     | `verify` | Atendido                                                            |
| R06  | Rejeitar assinaturas inválidas/adulteração | `verify` | Atendido (código 1 e mensagem "INVÁLIDA")                           |

Tratamento de erros: arquivo inexistente, diretório no lugar de arquivo, caminho de destino inválido,
PEM corrompido, chave incompatível, hash de referência malformado e assinatura truncada, todos com mensagem
compreensível e código ≠ 0.

## 7.4 Testes Realizados

Execução: `python -m unittest discover -s tests -v` → **34 testes, todos aprovados**
(evidência: `docs/evidencias/execucao_testes.txt`; fluxo ponta a ponta em `docs/evidencias/execucao_demo.txt`).

| ID   | Teste                                          | Resultado esperado  | Resultado obtido                      | Evidência     |
| ---- | ---------------------------------------------- | ------------------- | ------------------------------------- | ------------- |
| TI01 | SHA-256 de um arquivo                          | Hash correto        | Aprovado (inclui vetor NIST de "abc") | `test_TI01_*` |
| TI02 | Modificar arquivo e comparar com hash original | Divergência         | Aprovado (código 1)                   | `test_TI02_*` |
| TI03 | Gerar par de chaves                            | PEM válidos         | Aprovado (PKCS#8 / SPKI)              | `test_TI03_*` |
| TI04 | Assinar e verificar original                   | Assinatura válida   | Aprovado (código 0)                   | `test_TI04_*` |
| TI05 | Alterar arquivo após assinatura                | Assinatura inválida | Aprovado (código 1)                   | `test_TI05_*` |
| TI06 | Verificar com outra chave pública              | Assinatura inválida | Aprovado (código 1)                   | `test_TI06_*` |

Testes adicionais: interoperabilidade bidirecional com OpenSSL, assinatura de 64 bytes, dados binários,
arquivo vazio, não normalização de fim de linha, bit alterado na assinatura e demais cenários de erro e uso incorreto.

## 7.5 Análise Técnica e Conclusão

**Limitações.** Chave privada armazenada em PEM sem senha; não há identidade vinculada à chave pública
(sem certificados/PKI); sem carimbo de tempo, revogação ou rotação de chaves; um arquivo por operação
(sem lote); a assinatura fica em arquivo separado, sem metadados (autor, data); mensagens em português apenas.

**1. Por que um hash SHA-256 isolado não comprova autoria?** O hash apenas resume o conteúdo e pode ser
calculado por qualquer pessoa. Garante, no máximo, integridade em relação a uma referência confiável, mas
não identifica quem o produziu; um atacante pode alterar o documento e publicar o novo hash.

**2. Qual é a função das chaves pública e privada?** A chave privada, mantida em sigilo pelo signatário,
produz a assinatura. A chave pública, distribuível livremente, permite que qualquer um verifique que a
assinatura foi produzida pela chave privada correspondente e sobre aquele conteúdo, sem revelar a privada.

**3. Por que alterar um documento assinado invalida a assinatura?** A assinatura Ed25519 depende
matematicamente dos bytes exatos assinados. Qualquer mudança, mesmo de um único bit, altera a entrada da
verificação e a equação deixa de se satisfazer, tornando a assinatura inválida.

**4. Cuidados para produção.** Proteger a chave privada (senha/KDF, HSM ou cofre de chaves); associar a
chave pública a uma identidade confiável (certificados/PKI) e distribuí-la por canal autenticado; prever
rotação e revogação; adotar carimbo de tempo; manter logs de auditoria e controle de acesso; fazer backup
seguro; manter dependências atualizadas; e submeter a solução a revisão de segurança.
