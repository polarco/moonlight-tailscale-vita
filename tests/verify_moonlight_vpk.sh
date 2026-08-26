#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
vpk=${1:-"$project_dir/dist/Moonlight-Tailscale-Vita-v0.1.8.vpk"}
elf=${2:-"$project_dir/build/moonlight-tailscale/upstream/moonlight.elf"}
vitasdk=${VITASDK:-"$project_dir/../.tools/vitasdk"}
readelf="$vitasdk/bin/arm-vita-eabi-readelf"
nm="$vitasdk/bin/arm-vita-eabi-nm"

test -f "$vpk"
test -f "$elf"
test -x "$readelf"
test -x "$nm"

unzip -tqq "$vpk"
archive_list=$(unzip -Z1 "$vpk")

for entry in \
    sce_sys/param.sfo \
    eboot.bin \
    sce_sys/icon0.png \
    sce_sys/livearea/contents/bg.png \
    sce_sys/livearea/contents/startup.png \
    sce_sys/livearea/contents/template.xml \
    assets/nerdfont.ttf \
    THIRD_PARTY_NOTICES.md; do
    printf '%s\n' "$archive_list" | awk -v wanted="$entry" \
        '$0 == wanted { found = 1 } END { exit !found }'
done

if printf '%s\n' "$archive_list" | grep -Eqi '(^|/)(wg-private\.key|wg-peer\.conf)$'; then
    echo "erro: material de identidade/configuracao entrou no VPK" >&2
    exit 1
fi

sfo_strings=$(unzip -p "$vpk" sce_sys/param.sfo | strings)
printf '%s\n' "$sfo_strings" | awk '$0 == "TSVITAML1" { found = 1 } END { exit !found }'
printf '%s\n' "$sfo_strings" | awk '$0 == "Moonlight Tailscale" { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "moonlight-tunnel.log") { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "tsvita-network.log") { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "Moonlight Tailscale Adapter 0.1.8") { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "F_SETFD") { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "poll lwip-fatiado") { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "SO_RCVTIMEO udp-fallback") { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "WireGuard replay-window=%u bits") { found = 1 } END { exit !found }'
strings "$elf" | \
    awk '$0 == "replay/janela" { found = 1 } END { exit !found }'
strings "$elf" | \
    awk 'index($0, "motivo=%s total=%llu") { found = 1 } END { exit !found }'

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
    tsvita_trace \
    tsvita_tunnel_ensure_started; do
    "$nm" "$elf" | awk -v wanted="$symbol" \
        '$3 == wanted { found = 1 } END { exit !found }'
done

printf 'VPK Moonlight validado: %s\n' "$vpk"
sha256sum "$vpk"
