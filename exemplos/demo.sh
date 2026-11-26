#!/usr/bin/env bash
# Demonstração completa do fluxo. Execute a partir da raiz do repositório:
#   bash exemplos/demo.sh
set -u
CLI="python3 src/seguranca.py"
TMP="$(mktemp -d)"
DOC="exemplos/documento_ficticio.txt"
trap 'rm -rf "$TMP"' EXIT

echo "== 1. Gerar chaves ==";            $CLI keygen "$TMP/priv.pem" "$TMP/pub.pem"
echo "== 2. Hash SHA-256 ==";            H=$($CLI hash "$DOC"); echo "$H"
echo "== 3. Conferir hash ==";           $CLI check "$DOC" "$H"; echo "código de saída: $?"
echo "== 4. Assinar ==";                 $CLI sign "$DOC" "$TMP/priv.pem" "$TMP/doc.sig"
echo "== 5. Verificar (original) ==";    $CLI verify "$DOC" "$TMP/pub.pem" "$TMP/doc.sig"; echo "código de saída: $?"
echo "== 6. Adulterar e verificar ==";   cp "$DOC" "$TMP/adulterado.txt"; echo "x" >> "$TMP/adulterado.txt"
$CLI verify "$TMP/adulterado.txt" "$TMP/pub.pem" "$TMP/doc.sig"; echo "código de saída: $?"
echo "== 7. Outra chave pública ==";     $CLI keygen "$TMP/p2.pem" "$TMP/q2.pem" >/dev/null
$CLI verify "$DOC" "$TMP/q2.pem" "$TMP/doc.sig"; echo "código de saída: $?"
