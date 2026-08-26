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

moonlight_dir="$project_dir/.deps/vita-moonlight"
moonlight_commit="984603bd6f93f752593048fe494b5ffca14514e1"
wireguard_dir="$project_dir/.deps/wireguard-lwip"
wireguard_commit="c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d"
wireguard_patch="$project_dir/patches/wireguard-lwip-replay-window.patch"
lwip_dir="$project_dir/.deps/lwip"
lwip_commit="77dcd25a72509eb83f72b033d219b1d40cd8eb95"
moonlight_patch="$project_dir/patches/vita-moonlight-tsvita-diagnostics.patch"
build_dir="$project_dir/build/moonlight-tailscale"
dist_dir="$project_dir/dist"

if [ ! -d "$moonlight_dir/.git" ]; then
  mkdir -p "$project_dir/.deps"
  git clone --branch 0.13.2 --single-branch --recurse-submodules \
    https://github.com/xyzz/vita-moonlight.git "$moonlight_dir"
fi

git -C "$moonlight_dir" submodule update --init --recursive

if [ "$(git -C "$moonlight_dir" rev-parse HEAD)" != "$moonlight_commit" ]; then
  echo "Moonlight inesperado em $moonlight_dir" >&2
  exit 1
fi
if [ "$(git -C "$wireguard_dir" rev-parse HEAD)" != "$wireguard_commit" ]; then
  echo "wireguard-lwip inesperado em $wireguard_dir" >&2
  exit 1
fi
if [ "$(git -C "$lwip_dir" rev-parse HEAD)" != "$lwip_commit" ]; then
  echo "lwIP inesperada em $lwip_dir" >&2
  exit 1
fi

if git -C "$wireguard_dir" apply --reverse --check "$wireguard_patch" 2>/dev/null; then
  :
elif git -C "$wireguard_dir" apply --check "$wireguard_patch"; then
  git -C "$wireguard_dir" apply "$wireguard_patch"
else
  echo "Patch WireGuard nao pode ser aplicado com seguranca" >&2
  exit 1
fi

if git -C "$moonlight_dir" apply --reverse --check "$moonlight_patch" 2>/dev/null; then
  :
elif git -C "$moonlight_dir" apply --check "$moonlight_patch"; then
  git -C "$moonlight_dir" apply "$moonlight_patch"
else
  echo "Patch Moonlight nao pode ser aplicado com seguranca" >&2
  exit 1
fi

cmake -S "$project_dir/moonlight" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build "$build_dir" --target moonlight_tailscale_vpk --parallel 2
cmake -E make_directory "$dist_dir"
cmake -E copy_if_different \
  "$build_dir/Moonlight-Tailscale-Vita-v0.1.8.vpk" \
  "$dist_dir/Moonlight-Tailscale-Vita-v0.1.8.vpk"

"$project_dir/tests/verify_moonlight_vpk.sh" \
  "$dist_dir/Moonlight-Tailscale-Vita-v0.1.8.vpk" \
  "$build_dir/upstream/moonlight.elf"

echo "VPK criado em $dist_dir/Moonlight-Tailscale-Vita-v0.1.8.vpk"
