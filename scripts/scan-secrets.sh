#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

if git ls-files | grep -Eqi '(^|/)(\.env($|\.)|wg-private\.key|wg-peer\.conf|id_(rsa|ed25519)|[^/]*\.(pem|p12|pfx|pcap|pcapng))$'; then
  echo "erro: arquivo privado rastreado pelo Git" >&2
  exit 1
fi

if git grep -n -I -E \
    -- '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|tailscale-auth-key|tskey-(auth|client|api)-|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}' \
    -- . ':!scripts/scan-secrets.sh' ':!tests/scan-secrets-fixtures/**'; then
  echo "erro: padrao de segredo encontrado" >&2
  exit 1
fi

echo "OK: scan de segredos rastreados"
