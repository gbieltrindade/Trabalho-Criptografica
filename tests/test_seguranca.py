"""Testes automatizados da ferramenta `seguranca`.

Executa a CLI como processo externo (subprocess), exatamente como um
usuário/avaliador faria, e confere saída e código de retorno.

Execução (a partir da raiz do repositório):
    python -m unittest discover -s tests -v

TI01..TI06 correspondem aos testes mínimos do enunciado.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(RAIZ, "src", "seguranca.py")
CONTEUDO = "CERTIFICADO FICTÍCIO\nAluno: Fulano de Tal (dados fictícios)\n".encode("utf-8")


def executar(*args):
    return subprocess.run(
        [sys.executable, CLI, *map(str, args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


class BaseTeste(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="seguranca_test_")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.doc = self.caminho("documento.txt")
        self.escrever(self.doc, CONTEUDO)

    def caminho(self, nome):
        return os.path.join(self.dir, nome)

    @staticmethod
    def escrever(caminho, dados):
        with open(caminho, "wb") as f:
            f.write(dados)

    @staticmethod
    def ler(caminho):
        with open(caminho, "rb") as f:
            return f.read()

    def gerar_chaves(self, prefixo=""):
        priv = self.caminho(f"{prefixo}priv.pem")
        pub = self.caminho(f"{prefixo}pub.pem")
        r = executar("keygen", priv, pub)
        self.assertEqual(r.returncode, 0, r.stderr)
        return priv, pub

    def assinar(self, priv, nome="assinatura.sig"):
        sig = self.caminho(nome)
        r = executar("sign", self.doc, priv, sig)
        self.assertEqual(r.returncode, 0, r.stderr)
        return sig


# ----------------------------------------------------------------------
# Testes mínimos do enunciado (TI01 - TI06)
# ----------------------------------------------------------------------
class TestesMinimos(BaseTeste):
    def test_TI01_hash_correto(self):
        esperado = hashlib.sha256(CONTEUDO).hexdigest()
        r = executar("hash", self.doc)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), esperado)
        self.assertRegex(r.stdout.strip(), r"^[0-9a-f]{64}$")

    def test_TI01_hash_vetor_conhecido(self):
        # Vetor de teste NIST/RFC: SHA-256("abc")
        self.escrever(self.doc, b"abc")
        r = executar("hash", self.doc)
        self.assertEqual(
            r.stdout.strip(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_TI02_arquivo_modificado_diverge(self):
        original = executar("hash", self.doc).stdout.strip()
        r_ok = executar("check", self.doc, original)
        self.assertEqual(r_ok.returncode, 0)
        self.assertIn("CONFERE", r_ok.stdout)
        self.escrever(self.doc, CONTEUDO + b" ")  # alteração mínima
        r = executar("check", self.doc, original)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("DIVERGENTE", r.stdout)

    def test_TI03_gera_par_de_chaves_pem(self):
        priv, pub = self.gerar_chaves()
        txt_priv = self.ler(priv).decode()
        txt_pub = self.ler(pub).decode()
        self.assertTrue(txt_priv.startswith("-----BEGIN PRIVATE KEY-----"))  # PKCS#8
        self.assertTrue(txt_pub.startswith("-----BEGIN PUBLIC KEY-----"))  # SPKI

    def test_TI04_assina_e_verifica_original(self):
        priv, pub = self.gerar_chaves()
        sig = self.assinar(priv)
        r = executar("verify", self.doc, pub, sig)
        self.assertEqual(r.returncode, 0)
        self.assertIn("VÁLIDA", r.stdout)
        self.assertNotIn("INVÁLIDA", r.stdout)

    def test_TI05_arquivo_alterado_apos_assinatura(self):
        priv, pub = self.gerar_chaves()
        sig = self.assinar(priv)
        self.escrever(self.doc, CONTEUDO.replace(b"Fulano", b"Beltrano"))
        r = executar("verify", self.doc, pub, sig)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("INVÁLIDA", r.stdout)

    def test_TI06_outra_chave_publica(self):
        priv, _ = self.gerar_chaves()
        _, outra_pub = self.gerar_chaves("outra_")
        sig = self.assinar(priv)
        r = executar("verify", self.doc, outra_pub, sig)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("INVÁLIDA", r.stdout)


# ----------------------------------------------------------------------
# Contrato de interoperabilidade
# ----------------------------------------------------------------------
class TestesContrato(BaseTeste):
    def test_assinatura_tem_exatamente_64_bytes(self):
        priv, _ = self.gerar_chaves()
        sig = self.assinar(priv)
        self.assertEqual(len(self.ler(sig)), 64)

    def test_assinatura_ed25519_e_deterministica(self):
        priv, _ = self.gerar_chaves()
        s1 = self.ler(self.assinar(priv, "a.sig"))
        s2 = self.ler(self.assinar(priv, "b.sig"))
        self.assertEqual(s1, s2)

    def test_bytes_binarios_arbitrarios(self):
        dados = bytes(range(256)) * 50 + b"\r\n\x00\xff"
        self.escrever(self.doc, dados)
        r = executar("hash", self.doc)
        self.assertEqual(r.stdout.strip(), hashlib.sha256(dados).hexdigest())
        priv, pub = self.gerar_chaves()
        sig = self.assinar(priv)
        self.assertEqual(executar("verify", self.doc, pub, sig).returncode, 0)

    def test_arquivo_vazio(self):
        self.escrever(self.doc, b"")
        r = executar("hash", self.doc)
        self.assertEqual(r.stdout.strip(), hashlib.sha256(b"").hexdigest())

    def test_fim_de_linha_nao_e_normalizado(self):
        self.escrever(self.doc, b"linha\r\n")
        h_crlf = executar("hash", self.doc).stdout.strip()
        self.escrever(self.doc, b"linha\n")
        h_lf = executar("hash", self.doc).stdout.strip()
        self.assertNotEqual(h_crlf, h_lf)

    def test_check_aceita_referencia_em_maiusculas(self):
        h = executar("hash", self.doc).stdout.strip()
        self.assertEqual(executar("check", self.doc, h.upper()).returncode, 0)

    def test_chave_privada_pkcs8_e_publica_spki_validas(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        priv, pub = self.gerar_chaves()
        k_priv = serialization.load_pem_private_key(self.ler(priv), password=None)
        k_pub = serialization.load_pem_public_key(self.ler(pub))
        self.assertIsInstance(k_priv, Ed25519PrivateKey)
        self.assertIsInstance(k_pub, Ed25519PublicKey)

    @unittest.skipUnless(os.name == "posix", "permissões POSIX")
    def test_chave_privada_com_permissao_restrita(self):
        priv, _ = self.gerar_chaves()
        self.assertEqual(os.stat(priv).st_mode & 0o777, 0o600)


# ----------------------------------------------------------------------
# Interoperabilidade real com OpenSSL (implementação independente)
# ----------------------------------------------------------------------
def _openssl_suporta_ed25519():
    exe = shutil.which("openssl")
    if not exe:
        return False
    r = subprocess.run([exe, "genpkey", "-algorithm", "ed25519"],
                       capture_output=True, text=True)
    return r.returncode == 0


@unittest.skipUnless(_openssl_suporta_ed25519(), "OpenSSL com Ed25519 não disponível")
class TestesInteropOpenSSL(BaseTeste):
    def test_openssl_verifica_assinatura_gerada_pela_ferramenta(self):
        priv, pub = self.gerar_chaves()
        sig = self.assinar(priv)
        r = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub,
             "-rawin", "-in", self.doc, "-sigfile", sig],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_ferramenta_verifica_assinatura_gerada_pelo_openssl(self):
        priv = self.caminho("o_priv.pem")
        pub = self.caminho("o_pub.pem")
        sig = self.caminho("o.sig")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", priv],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", priv, "-pubout", "-out", pub],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", priv, "-rawin",
                        "-in", self.doc, "-out", sig], check=True, capture_output=True)
        r = executar("verify", self.doc, pub, sig)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # e a mesma chave privada do OpenSSL deve funcionar no sign
        sig2 = self.caminho("ferramenta.sig")
        self.assertEqual(executar("sign", self.doc, priv, sig2).returncode, 0)
        self.assertEqual(self.ler(sig), self.ler(sig2))  # Ed25519 é determinístico


# ----------------------------------------------------------------------
# Tratamento de erros
# ----------------------------------------------------------------------
class TestesErros(BaseTeste):
    def assertErro(self, r, trecho=None):
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn("VÁLIDA: ", r.stdout.replace("INVÁLIDA", ""))
        if trecho:
            self.assertIn(trecho, r.stderr + r.stdout)

    def test_hash_arquivo_inexistente(self):
        self.assertErro(executar("hash", self.caminho("nao_existe.txt")), "não encontrado")

    def test_hash_de_diretorio(self):
        self.assertErro(executar("hash", self.dir), "diretório")

    def test_check_referencia_malformada(self):
        self.assertErro(executar("check", self.doc, "1234"), "hash de referência inválido")

    def test_check_arquivo_inexistente(self):
        self.assertErro(executar("check", self.caminho("x"), "0" * 64), "não encontrado")

    def test_sign_chave_inexistente(self):
        r = executar("sign", self.doc, self.caminho("nao.pem"), self.caminho("s.sig"))
        self.assertErro(r, "não encontrado")
        self.assertFalse(os.path.exists(self.caminho("s.sig")))

    def test_sign_arquivo_inexistente(self):
        priv, _ = self.gerar_chaves()
        r = executar("sign", self.caminho("nao.txt"), priv, self.caminho("s.sig"))
        self.assertErro(r, "não encontrado")

    def test_sign_com_chave_publica_no_lugar_da_privada(self):
        _, pub = self.gerar_chaves()
        r = executar("sign", self.doc, pub, self.caminho("s.sig"))
        self.assertErro(r, "chave privada PEM")

    def test_sign_com_pem_corrompido(self):
        lixo = self.caminho("lixo.pem")
        self.escrever(lixo, b"isto nao e uma chave")
        self.assertErro(executar("sign", self.doc, lixo, self.caminho("s.sig")))

    def test_verify_chave_incompativel_rsa(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl ausente")
        priv, _ = self.gerar_chaves()
        sig = self.assinar(priv)
        rsa_priv = self.caminho("rsa.pem")
        rsa_pub = self.caminho("rsa_pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", rsa_priv],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", rsa_priv, "-pubout", "-out", rsa_pub],
                       check=True, capture_output=True)
        self.assertErro(executar("verify", self.doc, rsa_pub, sig), "incompatível")

    def test_verify_assinatura_inexistente(self):
        _, pub = self.gerar_chaves()
        self.assertErro(executar("verify", self.doc, pub, self.caminho("n.sig")), "não encontrado")

    def test_verify_assinatura_tamanho_incorreto(self):
        _, pub = self.gerar_chaves()
        sig = self.caminho("curta.sig")
        self.escrever(sig, b"\x00" * 10)
        r = executar("verify", self.doc, pub, sig)
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVÁLIDA", r.stdout)

    def test_verify_assinatura_com_bit_alterado(self):
        priv, pub = self.gerar_chaves()
        sig = self.assinar(priv)
        dados = bytearray(self.ler(sig))
        dados[0] ^= 0x01
        self.escrever(sig, bytes(dados))
        r = executar("verify", self.doc, pub, sig)
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVÁLIDA", r.stdout)

    def test_keygen_nao_sobrescreve_sem_force(self):
        priv, pub = self.gerar_chaves()
        antes = self.ler(priv)
        r = executar("keygen", priv, pub)
        self.assertErro(r, "já existe")
        self.assertEqual(self.ler(priv), antes)
        self.assertEqual(executar("keygen", priv, pub, "--force").returncode, 0)
        self.assertNotEqual(self.ler(priv), antes)

    def test_keygen_diretorio_destino_inexistente(self):
        r = executar("keygen", self.caminho("sub/p.pem"), self.caminho("sub/q.pem"))
        self.assertErro(r, "inexistente")

    def test_keygen_mesmos_caminhos(self):
        p = self.caminho("mesmo.pem")
        self.assertErro(executar("keygen", p, p), "diferentes")

    def test_sem_argumentos_retorna_erro(self):
        r = executar()
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)

    def test_argumentos_faltando(self):
        r = executar("verify", self.doc)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
