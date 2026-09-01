#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
image="vitasdk/vitasdk:2026.08-20260815"

if ! command -v docker >/dev/null 2>&1; then
  echo "erro: Docker e necessario para o build VitaSDK imutavel" >&2
  exit 1
fi

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$project_dir:/workspace" \
  --workdir /workspace \
  "$image" \
  sh -lc './scripts/build-moonlight.sh'

runtime_version=$(sed -n '1p' "$project_dir/VERSION")
"$project_dir/tests/verify_moonlight_vpk.sh" \
  "$project_dir/dist/Moonlight-Tailscale-Vita-v${runtime_version}.vpk" \
  "$project_dir/build/moonlight-tailscale/upstream/moonlight.elf" \
  "$project_dir/build/moonlight-tailscale/moonlight-tailscale-eboot.bin"
