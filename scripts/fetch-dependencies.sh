#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dependency_root="$project_dir/.deps"

moonlight_url="https://github.com/xyzz/vita-moonlight.git"
moonlight_commit="984603bd6f93f752593048fe494b5ffca14514e1"
wireguard_url="https://github.com/smartalock/wireguard-lwip.git"
wireguard_commit="c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d"
lwip_url="https://github.com/lwip-tcpip/lwip.git"
lwip_commit="77dcd25a72509eb83f72b033d219b1d40cd8eb95"

fetch_pinned_repository() {
  name=$1
  url=$2
  commit=$3
  destination="$dependency_root/$name"

  if [ ! -d "$destination/.git" ]; then
    git clone --filter=blob:none --no-checkout "$url" "$destination"
    git -C "$destination" fetch --depth 1 origin "$commit"
    git -C "$destination" checkout --detach "$commit"
  fi

  actual_commit=$(git -C "$destination" rev-parse HEAD)
  if [ "$actual_commit" != "$commit" ]; then
    echo "$name inesperado: $actual_commit (esperado: $commit)" >&2
    exit 1
  fi
}

mkdir -p "$dependency_root"
fetch_pinned_repository vita-moonlight "$moonlight_url" "$moonlight_commit"
git -C "$dependency_root/vita-moonlight" submodule update --init --recursive
fetch_pinned_repository wireguard-lwip "$wireguard_url" "$wireguard_commit"
fetch_pinned_repository lwip "$lwip_url" "$lwip_commit"

echo "Dependencias fixadas e verificadas."
