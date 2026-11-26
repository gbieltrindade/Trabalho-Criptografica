# seguranca — Integridade e Assinatura Digital (SHA-256 + Ed25519)

Ferramenta de linha de comando (CLI) desenvolvida para o **Trabalho Prático — Etapa 1**
de Segurança da Informação. Calcula e compara hashes SHA-256, gera chaves Ed25519,
assina arquivos e verifica assinaturas.

- **Linguagem:** Python 3.9+ (testado em 3.12)
- **Biblioteca criptográfica:** [`cryptography`](https://cryptography.io) (mantida pela PyCA)
- **Integrantes:** Ester Marina, Gabriel Trindade, Lorena Alice
- **Turma:** 5 / V

---

## 1. Instalação

Requisitos: Python 3.9 ou superior e `pip`.

```bash
git clone https://github.com/gbieltrindade/Trabalho-Criptografica.git
cd Trabalho-Criptografica

# (recomendado) ambiente virtual
python3 -m venv .venv
source .venv/bin/activate          # Windows (PowerShell): .venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## 2. Execução

O comando lógico `seguranca` corresponde a **`python src/seguranca.py`**
(no Windows, use `python` ou `py`; no Linux/macOS pode ser `python3`).

| Operação             | Comando exato                                                                   |
| -------------------- | ------------------------------------------------------------------------------- |
| Gerar chaves         | `python src/seguranca.py keygen chave_privada.pem chave_publica.pem`            |
| Calcular hash        | `python src/seguranca.py hash documento.txt`                                    |
| Comparar hash        | `python src/seguranca.py check documento.txt HASH_REFERENCIA`                   |
| Assinar arquivo      | `python src/seguranca.py sign documento.txt chave_privada.pem assinatura.sig`   |
| Verificar assinatura | `python src/seguranca.py verify documento.txt chave_publica.pem assinatura.sig` |

A ordem dos argumentos é exatamente a do enunciado. Ajuda: `python src/seguranca.py --help`.

Opção extra: `--force` em `keygen` e `sign` permite sobrescrever arquivos existentes
(por padrão a ferramenta **não** sobrescreve, para evitar perda acidental de chaves).

### Códigos de saída

| Código | Significado                                                                      |
| ------ | -------------------------------------------------------------------------------- |
| `0`    | Sucesso (hash confere / assinatura válida / operação concluída)                  |
| `1`    | Verificação falhou (hash diverge / assinatura inválida)                          |
| `2`    | Erro (arquivo inexistente, chave incompatível, PEM inválido, uso incorreto etc.) |

`check` e `verify` **nunca** retornam `0` quando a verificação falha ou há erro.

## 3. Exemplo completo

```bash
python src/seguranca.py keygen priv.pem pub.pem
python src/seguranca.py hash exemplos/documento_ficticio.txt
python src/seguranca.py check exemplos/documento_ficticio.txt <hash_exibido_acima>
python src/seguranca.py sign exemplos/documento_ficticio.txt priv.pem doc.sig
python src/seguranca.py verify exemplos/documento_ficticio.txt pub.pem doc.sig   # VÁLIDA (exit 0)

# adulteração
cp exemplos/documento_ficticio.txt copia.txt && echo "x" >> copia.txt
python src/seguranca.py verify copia.txt pub.pem doc.sig                          # INVÁLIDA (exit 1)
```

Demonstração automática (Linux/macOS/Git Bash): `bash exemplos/demo.sh`.
A saída de uma execução real está em `docs/evidencias/execucao_demo.txt`.

## 4. Contrato de interoperabilidade (como a ferramenta se comporta)

| Item                | Implementação                                                        |
| ------------------- | -------------------------------------------------------------------- |
| Hash                | SHA-256, 64 caracteres hexadecimais **minúsculos**                   |
| Assinatura          | Ed25519 aplicada **diretamente aos bytes** do arquivo (sem pré-hash) |
| Chave pública       | PEM, SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`)             |
| Chave privada       | PEM, PKCS#8 (`-----BEGIN PRIVATE KEY-----`), sem senha               |
| Arquivo `.sig`      | Binário, exatamente 64 bytes                                         |
| Leitura de arquivos | Binária, sem normalização de codificação/fim de linha                |

Interoperabilidade verificada contra o **OpenSSL** (implementação independente) nos testes
automatizados: assinaturas geradas pela ferramenta são aceitas pelo OpenSSL e vice-versa.

Para validar manualmente com OpenSSL 3.x:

```bash
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in documento.txt -sigfile doc.sig
```

## 5. Testes automatizados

Usam apenas a biblioteca padrão (`unittest`) — nenhuma dependência extra além da `cryptography`.

```bash
python -m unittest discover -s tests -v
```

| ID   | Teste                                          | Resultado esperado  | Função de teste                                            |
| ---- | ---------------------------------------------- | ------------------- | ---------------------------------------------------------- |
| TI01 | SHA-256 de um arquivo                          | Hash correto        | `test_TI01_hash_correto`, `test_TI01_hash_vetor_conhecido` |
| TI02 | Modificar arquivo e comparar com hash original | Divergência         | `test_TI02_arquivo_modificado_diverge`                     |
| TI03 | Gerar par de chaves                            | PEM válidos         | `test_TI03_gera_par_de_chaves_pem`                         |
| TI04 | Assinar e verificar original                   | Assinatura válida   | `test_TI04_assina_e_verifica_original`                     |
| TI05 | Alterar arquivo após assinar                   | Assinatura inválida | `test_TI05_arquivo_alterado_apos_assinatura`               |
| TI06 | Verificar com outra chave pública              | Assinatura inválida | `test_TI06_outra_chave_publica`                            |

Além dos TI01–TI06, a suíte cobre: assinatura de 64 bytes, formato PKCS#8/SPKI, dados binários
arbitrários, arquivo vazio, ausência de normalização de fim de linha, interoperabilidade com
OpenSSL e tratamento de erros (arquivo inexistente, diretório, PEM corrompido, chave pública no
lugar da privada, chave RSA incompatível, assinatura truncada ou com bit alterado, etc.).
Total: **34 testes**. Há também um workflow do GitHub Actions (`.github/workflows/tests.yml`).

Todos os dados de teste são fictícios.

## 6. Estrutura do repositório

```
seguranca-grupo-XX/
├── README.md
├── requirements.txt
├── src/seguranca.py
├── tests/test_seguranca.py
├── exemplos/            (documento fictício e demo.sh)
├── docs/
│   ├── RELATORIO_TECNICO.md
│   └── evidencias/      (saídas reais dos testes e da demo)
└── .github/workflows/tests.yml
```

## 7. Segurança das chaves

As chaves geradas **não devem ser versionadas**: o `.gitignore` bloqueia `*.pem` e `*.sig`.
Use chaves privadas apenas em contexto didático; nunca publique chaves reais.
