#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
runtime_version=$(sed -n '1p' "$project_dir/VERSION")
vpk=${1:-"$project_dir/dist/Moonlight-Tailscale-Vita-v${runtime_version}.vpk"}
elf=${2:-"$project_dir/build/moonlight-tailscale/upstream/moonlight.elf"}
eboot=${3:-"$project_dir/build/moonlight-tailscale/moonlight-tailscale-eboot.bin"}
vitasdk=${VITASDK:-"$project_dir/../.tools/vitasdk"}
readelf="$vitasdk/bin/arm-vita-eabi-readelf"
nm="$vitasdk/bin/arm-vita-eabi-nm"
if [ ! -x "$readelf" ]; then readelf=$(command -v readelf); fi
if [ ! -x "$nm" ]; then nm=$(command -v nm); fi

for artifact in "$vpk" "$elf" "$eboot"; do
  if [ ! -f "$artifact" ]; then
    echo "erro: artefato obrigatorio ausente: $artifact" >&2
    exit 1
  fi
done

unzip -tqq "$vpk"
archive_list=$(unzip -Z1 "$vpk")
if [ -z "$archive_list" ]; then
  echo "erro: VPK vazio" >&2
  exit 1
fi

if ! printf '%s\n' "$archive_list" | awk '
  { if (seen[$0]++) { print "erro: entrada duplicada: " $0 > "/dev/stderr"; bad=1 } }
  END { exit bad }
'; then
  exit 1
fi

if printf '%s\n' "$archive_list" | awk '
  /\\/ || /^\// || /^[A-Za-z]:\// || /(^|\/)\.\.?($|\/)/ {
    print "erro: caminho inseguro: " $0 > "/dev/stderr"; bad=1
  }
  END { exit bad }
'; then
  :
else
  exit 1
fi

for entry in \
    sce_sys/param.sfo \
    eboot.bin \
    sce_sys/icon0.png \
    sce_sys/livearea/contents/bg.png \
    sce_sys/livearea/contents/startup.png \
    sce_sys/livearea/contents/template.xml \
    assets/nerdfont.ttf \
    THIRD_PARTY_NOTICES.md; do
  count=$(printf '%s\n' "$archive_list" | awk -v wanted="$entry" '$0 == wanted { count++ } END { print count+0 }')
  if [ "$count" -ne 1 ]; then
    echo "erro: entrada obrigatoria deve existir exatamente uma vez: $entry" >&2
    exit 1
  fi
done

if printf '%s\n' "$archive_list" | grep -Eqi \
    '(^|/)(\.env($|\.)|wg-private\.key|wg-peer\.conf|id_(rsa|ed25519)|[^/]*\.(key|pem|p12|pfx|pcap|pcapng))$|(^|/)(private|secrets?|credentials?|tailscale)(/|$)'; then
  echo "erro: material privado, chave ou configuracao entrou no VPK" >&2
  exit 1
fi

extract_dir=$(mktemp -d)
trap 'rm -rf -- "$extract_dir"' EXIT HUP INT TERM
unzip -p "$vpk" eboot.bin > "$extract_dir/eboot.bin"
if ! cmp -s "$extract_dir/eboot.bin" "$eboot"; then
  echo "erro: eboot.bin empacotado nao pertence ao build informado" >&2
  exit 1
fi

test -n "$readelf" -a -x "$readelf"
test -n "$nm" -a -x "$nm"

sfo_strings=$(unzip -p "$vpk" sce_sys/param.sfo | strings)
printf '%s\n' "$sfo_strings" | awk '$0 == "TSVITAML1" { found = 1 } END { exit !found }'
printf '%s\n' "$sfo_strings" | awk '$0 == "Moonlight Tailscale" { found = 1 } END { exit !found }'
strings "$elf" | awk -v version="$runtime_version" \
    '$0 == version { found = 1 } END { exit !found }'
for marker in \
    moonlight-tunnel.log \
    tsvita-network.log \
    'Moonlight Tailscale Adapter %s' \
    F_SETFD \
    'poll lwip-fatiado' \
    'SO_RCVTIMEO udp-fallback' \
    'WireGuard replay-window=%u bits' \
    replay/janela \
    'session dur='; do
  strings "$elf" | awk -v wanted="$marker" \
      'index($0, wanted) { found = 1 } END { exit !found }'
done

"$readelf" -h "$elf" | awk '/Class:.*ELF32/ { found = 1 } END { exit !found }'
"$readelf" -h "$elf" | awk '/Machine:.*ARM/ { found = 1 } END { exit !found }'

for symbol in \
    __wrap_socket \
    __wrap_connect \
    __wrap_send \
    __wrap_recv \
    __wrap_poll \
    __wrap_select \
    __wrap_getaddrinfo \
    lwip_socket \
    lwip_connect \
    tsvita_peer_config_parse \
    tsvita_scheduler_tick \
    tsvita_session_begin \
    tsvita_session_end \
    tsvita_trace \
    tsvita_tunnel_ensure_started; do
  "$nm" "$elf" | awk -v wanted="$symbol" \
      '$3 == wanted { found = 1 } END { exit !found }'
done

printf 'VPK Moonlight validado: %s\n' "$vpk"
sha256sum "$vpk"
