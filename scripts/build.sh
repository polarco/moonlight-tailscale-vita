#!/usr/bin/env bash
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workspace_dir=$(CDPATH= cd -- "$project_dir/.." && pwd)

if [ -z "${VITASDK:-}" ]; then
  VITASDK="$workspace_dir/.tools/vitasdk"
fi
export VITASDK
export PATH="$VITASDK/bin:$PATH"

if [ ! -x "$VITASDK/bin/arm-vita-eabi-gcc" ]; then
  echo "VitaSDK nao encontrado em: $VITASDK" >&2
  exit 1
fi

"$project_dir/scripts/fetch-dependencies.sh"

build_dir="$project_dir/build"
dist_dir="$project_dir/dist"
dependency_dir="$project_dir/.deps/wireguard-lwip"
wireguard_commit="c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d"
lwip_dir="$project_dir/.deps/lwip"
lwip_commit="77dcd25a72509eb83f72b033d219b1d40cd8eb95"

if [ ! -d "$dependency_dir/.git" ]; then
  mkdir -p "$project_dir/.deps"
  git clone --filter=blob:none --no-checkout \
    https://github.com/smartalock/wireguard-lwip.git \
    "$dependency_dir"
  git -C "$dependency_dir" fetch --depth 1 origin "$wireguard_commit"
  git -C "$dependency_dir" checkout --detach "$wireguard_commit"
fi

if [ ! -d "$lwip_dir/.git" ]; then
  mkdir -p "$project_dir/.deps"
  git clone --filter=blob:none --no-checkout \
    https://github.com/lwip-tcpip/lwip.git \
    "$lwip_dir"
  git -C "$lwip_dir" fetch --depth 1 origin "$lwip_commit"
  git -C "$lwip_dir" checkout --detach "$lwip_commit"
fi

actual_lwip_commit=$(git -C "$lwip_dir" rev-parse HEAD)
if [ "$actual_lwip_commit" != "$lwip_commit" ]; then
  echo "lwIP inesperada em $lwip_dir" >&2
  echo "Esperado: $lwip_commit" >&2
  echo "Encontrado: $actual_lwip_commit" >&2
  exit 1
fi

actual_wireguard_commit=$(git -C "$dependency_dir" rev-parse HEAD)
if [ "$actual_wireguard_commit" != "$wireguard_commit" ]; then
  echo "wireguard-lwip inesperado em $dependency_dir" >&2
  echo "Esperado: $wireguard_commit" >&2
  echo "Encontrado: $actual_wireguard_commit" >&2
  exit 1
fi

cmake -S "$project_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" --parallel 2
cmake -E make_directory "$dist_dir"
cmake -E copy_if_different \
  "$build_dir/Tailscale-Vita-Probe-v0.8.0.vpk" \
  "$dist_dir/Tailscale-Vita-Probe-v0.8.0.vpk"
cmake -E copy_if_different \
  "$build_dir/Tailscale-Vita-WG-Crypto-Probe-v0.1.0.vpk" \
  "$dist_dir/Tailscale-Vita-WG-Crypto-Probe-v0.1.0.vpk"
cmake -E copy_if_different \
  "$build_dir/Tailscale-Vita-WG-Flow-Probe-v0.4.0.vpk" \
  "$dist_dir/Tailscale-Vita-WG-Flow-Probe-v0.4.0.vpk"

echo "VPK criado em $dist_dir/Tailscale-Vita-Probe-v0.8.0.vpk"
echo "VPK criado em $dist_dir/Tailscale-Vita-WG-Crypto-Probe-v0.1.0.vpk"
echo "VPK criado em $dist_dir/Tailscale-Vita-WG-Flow-Probe-v0.4.0.vpk"
