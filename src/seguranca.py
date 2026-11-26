#!/usr/bin/env python3
"""seguranca - Ferramenta CLI de integridade e assinatura digital.

Implementa SHA-256 e Ed25519 conforme o contrato de interoperabilidade
da disciplina Segurança da Informação (Trabalho Prático - Etapa 1).

Códigos de saída:
    0  sucesso (operação concluída / hash confere / assinatura válida)
    1  verificação falhou (hash diverge / assinatura inválida)
    2  erro de uso ou de execução (arquivo inexistente, chave incompatível etc.)
"""
import argparse
import hashlib
import hmac
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

EXIT_OK = 0
EXIT_VERIFICACAO_FALHOU = 1
EXIT_ERRO = 2

TAMANHO_ASSINATURA = 64
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class ErroFerramenta(Exception):
    """Erro tratável, com mensagem compreensível para o usuário."""


# ----------------------------------------------------------------------
# Utilitários de E/S
# ----------------------------------------------------------------------
def _validar_leitura(caminho, descricao):
    if not os.path.exists(caminho):
        raise ErroFerramenta(f"{descricao} não encontrado: '{caminho}'")
    if os.path.isdir(caminho):
        raise ErroFerramenta(f"'{caminho}' é um diretório, não um {descricao}")


def ler_bytes(caminho, descricao="arquivo"):
    """Lê um arquivo em modo binário, sem qualquer transformação."""
    _validar_leitura(caminho, descricao)
    try:
        with open(caminho, "rb") as f:
            return f.read()
    except PermissionError:
        raise ErroFerramenta(f"sem permissão para ler '{caminho}'")
    except OSError as e:
        raise ErroFerramenta(f"não foi possível ler '{caminho}': {e.strerror}")


def escrever_bytes(caminho, dados, privado=False, sobrescrever=False):
    """Grava bytes em arquivo. Não sobrescreve arquivos existentes sem --force."""
    diretorio = os.path.dirname(os.path.abspath(caminho))
    if not os.path.isdir(diretorio):
        raise ErroFerramenta(f"diretório de destino inexistente: '{diretorio}'")
    if os.path.isdir(caminho):
        raise ErroFerramenta(f"'{caminho}' é um diretório; informe um nome de arquivo")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if sobrescrever else os.O_EXCL)
    if hasattr(os, "O_BINARY"):  # Windows
        flags |= os.O_BINARY
    modo = 0o600 if privado else 0o644
    try:
        fd = os.open(caminho, flags, modo)
    except FileExistsError:
        raise ErroFerramenta(f"'{caminho}' já existe; use --force para sobrescrever")
    except PermissionError:
        raise ErroFerramenta(f"sem permissão para gravar em '{caminho}'")
    except OSError as e:
        raise ErroFerramenta(f"não foi possível gravar '{caminho}': {e.strerror}")
    with os.fdopen(fd, "wb") as f:
        f.write(dados)


# ----------------------------------------------------------------------
# Operações criptográficas
# ----------------------------------------------------------------------
def sha256_arquivo(caminho):
    """SHA-256 (64 hex minúsculos) calculado em blocos sobre os bytes originais."""
    _validar_leitura(caminho, "arquivo")
    h = hashlib.sha256()
    try:
        with open(caminho, "rb") as f:
            for bloco in iter(lambda: f.read(1024 * 1024), b""):
                h.update(bloco)
    except PermissionError:
        raise ErroFerramenta(f"sem permissão para ler '{caminho}'")
    except OSError as e:
        raise ErroFerramenta(f"não foi possível ler '{caminho}': {e.strerror}")
    return h.hexdigest()


def carregar_chave_privada(caminho):
    dados = ler_bytes(caminho, "arquivo de chave privada")
    try:
        chave = serialization.load_pem_private_key(dados, password=None)
    except TypeError:
        raise ErroFerramenta("a chave privada está protegida por senha (não suportado)")
    except Exception:
        raise ErroFerramenta(
            f"'{caminho}' não contém uma chave privada PEM (PKCS#8) válida"
        )
    if not isinstance(chave, Ed25519PrivateKey):
        raise ErroFerramenta("chave incompatível: a chave privada não é Ed25519")
    return chave


def carregar_chave_publica(caminho):
    dados = ler_bytes(caminho, "arquivo de chave pública")
    try:
        chave = serialization.load_pem_public_key(dados)
    except Exception:
        raise ErroFerramenta(
            f"'{caminho}' não contém uma chave pública PEM (SubjectPublicKeyInfo) válida"
        )
    if not isinstance(chave, Ed25519PublicKey):
        raise ErroFerramenta("chave incompatível: a chave pública não é Ed25519")
    return chave


# ----------------------------------------------------------------------
# Comandos
# ----------------------------------------------------------------------
def cmd_keygen(args):
    if os.path.abspath(args.chave_privada) == os.path.abspath(args.chave_publica):
        raise ErroFerramenta("os caminhos da chave privada e da pública devem ser diferentes")
    # Verifica ambos os destinos antes de gravar qualquer um.
    if not args.force:
        for c in (args.chave_privada, args.chave_publica):
            if os.path.exists(c):
                raise ErroFerramenta(f"'{c}' já existe; use --force para sobrescrever")
    privada = Ed25519PrivateKey.generate()
    pem_priv = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_pub = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    escrever_bytes(args.chave_privada, pem_priv, privado=True, sobrescrever=args.force)
    escrever_bytes(args.chave_publica, pem_pub, sobrescrever=args.force)
    print(f"Chave privada gravada em: {args.chave_privada}")
    print(f"Chave pública gravada em: {args.chave_publica}")
    print("ATENÇÃO: mantenha a chave privada em sigilo.")
    return EXIT_OK


def cmd_hash(args):
    print(sha256_arquivo(args.arquivo))
    return EXIT_OK


def cmd_check(args):
    referencia = args.hash_referencia.strip()
    if not _HEX64.match(referencia):
        raise ErroFerramenta(
            "hash de referência inválido: esperado 64 caracteres hexadecimais"
        )
    calculado = sha256_arquivo(args.arquivo)
    if hmac.compare_digest(calculado, referencia.lower()):
        print("HASH CONFERE: o arquivo corresponde ao hash de referência.")
        return EXIT_OK
    print("HASH DIVERGENTE: o arquivo NÃO corresponde ao hash de referência.")
    print(f"  calculado:  {calculado}")
    print(f"  referência: {referencia.lower()}")
    return EXIT_VERIFICACAO_FALHOU


def cmd_sign(args):
    dados = ler_bytes(args.arquivo, "arquivo")
    chave = carregar_chave_privada(args.chave_privada)
    assinatura = chave.sign(dados)  # Ed25519 direto sobre os bytes (sem pré-hash)
    if len(assinatura) != TAMANHO_ASSINATURA:
        raise ErroFerramenta("falha interna: assinatura com tamanho inesperado")
    escrever_bytes(args.assinatura, assinatura, sobrescrever=args.force)
    print(f"Assinatura gerada em: {args.assinatura} ({len(assinatura)} bytes)")
    return EXIT_OK


def cmd_verify(args):
    dados = ler_bytes(args.arquivo, "arquivo")
    chave = carregar_chave_publica(args.chave_publica)
    assinatura = ler_bytes(args.assinatura, "arquivo de assinatura")
    if len(assinatura) != TAMANHO_ASSINATURA:
        print(
            f"ASSINATURA INVÁLIDA: tamanho {len(assinatura)} bytes "
            f"(esperado {TAMANHO_ASSINATURA})."
        )
        return EXIT_VERIFICACAO_FALHOU
    try:
        chave.verify(assinatura, dados)
    except InvalidSignature:
        print(
            "ASSINATURA INVÁLIDA: o arquivo foi alterado ou a chave/assinatura "
            "não corresponde."
        )
        return EXIT_VERIFICACAO_FALHOU
    print(
        "ASSINATURA VÁLIDA: o arquivo é íntegro e foi assinado pela chave "
        "privada correspondente."
    )
    return EXIT_OK


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def construir_parser():
    p = argparse.ArgumentParser(
        prog="seguranca",
        description="Hash SHA-256 e assinatura digital Ed25519 de arquivos.",
    )
    sub = p.add_subparsers(dest="comando", required=True, metavar="comando")

    s = sub.add_parser("keygen", help="gera par de chaves Ed25519 (PEM)")
    s.add_argument("chave_privada", help="saída: chave privada (PKCS#8)")
    s.add_argument("chave_publica", help="saída: chave pública (SubjectPublicKeyInfo)")
    s.add_argument("--force", action="store_true", help="sobrescreve arquivos existentes")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("hash", help="calcula o SHA-256 de um arquivo")
    s.add_argument("arquivo")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("check", help="compara o SHA-256 do arquivo com uma referência")
    s.add_argument("arquivo")
    s.add_argument("hash_referencia", help="64 caracteres hexadecimais")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("sign", help="assina um arquivo com a chave privada")
    s.add_argument("arquivo")
    s.add_argument("chave_privada")
    s.add_argument("assinatura", help="saída: arquivo .sig (64 bytes)")
    s.add_argument("--force", action="store_true", help="sobrescreve a assinatura existente")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="verifica a assinatura de um arquivo")
    s.add_argument("arquivo")
    s.add_argument("chave_publica")
    s.add_argument("assinatura")
    s.set_defaults(func=cmd_verify)
    return p


def main(argv=None):
    parser = construir_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:  # argparse sai com 2 em erro de uso; 0 em --help
        return e.code if isinstance(e.code, int) else EXIT_ERRO
    try:
        return args.func(args)
    except ErroFerramenta as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return EXIT_ERRO
    except KeyboardInterrupt:
        print("ERRO: operação interrompida", file=sys.stderr)
        return EXIT_ERRO
    except Exception as e:  # nunca deixar uma falha inesperada parecer sucesso
        print(f"ERRO inesperado: {e}", file=sys.stderr)
        return EXIT_ERRO


if __name__ == "__main__":
    sys.exit(main())
