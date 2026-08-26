#!/usr/bin/env bash
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$project_dir/scripts/fetch-dependencies.sh"
test_build_dir="$project_dir/build/host-selftest"
dependency_dir="$project_dir/.deps/wireguard-lwip"
dependency_patch="$project_dir/patches/wireguard-lwip-replay-window.patch"

if git -C "$dependency_dir" apply --reverse --check "$dependency_patch" 2>/dev/null; then
  :
elif git -C "$dependency_dir" apply --check "$dependency_patch"; then
  git -C "$dependency_dir" apply "$dependency_patch"
else
  echo "Patch WireGuard nao pode ser aplicado com seguranca" >&2
  exit 1
fi

mkdir -p "$test_build_dir"

cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$project_dir/src" -I"$project_dir/src/compat" -I"$dependency_dir/src" \
  -c "$project_dir/tests/wireguard_handshake_selftest.c" \
  -o "$test_build_dir/selftest.o"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$project_dir/src" \
  -c "$project_dir/src/ipv4_literal.c" \
  -o "$test_build_dir/ipv4_literal.o"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$project_dir/src" \
  -c "$project_dir/src/ip_udp_packet.c" \
  -o "$test_build_dir/ip_udp_packet.o"

sources=(
  "$dependency_dir/src/wireguard.c"
  "$dependency_dir/src/crypto.c"
  "$dependency_dir/src/crypto/refc/blake2s.c"
  "$dependency_dir/src/crypto/refc/chacha20.c"
  "$dependency_dir/src/crypto/refc/chacha20poly1305.c"
  "$dependency_dir/src/crypto/refc/poly1305-donna.c"
  "$dependency_dir/src/crypto/refc/x25519.c"
)

objects=(
  "$test_build_dir/selftest.o"
  "$test_build_dir/ipv4_literal.o"
  "$test_build_dir/ip_udp_packet.o"
)
for source in "${sources[@]}"; do
  relative=${source#"$dependency_dir/src/"}
  object_name=${relative//\//_}
  object="$test_build_dir/$object_name.o"
  cc -std=c11 -O2 -Wno-stringop-overread \
    -I"$project_dir/src/compat" -I"$dependency_dir/src" \
    -c "$source" -o "$object"
  objects+=("$object")
done

cc "${objects[@]}" -o "$test_build_dir/wireguard_handshake_selftest"
"$test_build_dir/wireguard_handshake_selftest"

lwip_test_build_dir="$project_dir/build/host-lwip-selftest"
lwip_dir="$project_dir/.deps/lwip"
mkdir -p "$lwip_test_build_dir"

cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$project_dir/src" -I"$project_dir/src/lwip" \
  -I"$lwip_dir/src/include" \
  -c "$project_dir/tests/lwip_udp_selftest.c" \
  -o "$lwip_test_build_dir/selftest.o"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$project_dir/src" \
  -c "$project_dir/src/ip_udp_packet.c" \
  -o "$lwip_test_build_dir/ip_udp_packet.o"

lwip_objects=(
  "$lwip_test_build_dir/selftest.o"
  "$lwip_test_build_dir/ip_udp_packet.o"
)
while IFS= read -r source; do
  relative=${source#"$lwip_dir/src/"}
  object_name=${relative//\//_}
  object="$lwip_test_build_dir/$object_name.o"
  cc -std=c11 -O2 -Wall -Wextra \
    -I"$project_dir/src/lwip" -I"$lwip_dir/src/include" \
    -c "$source" -o "$object"
  lwip_objects+=("$object")
done < <(find "$lwip_dir/src/core" -maxdepth 1 -type f -name '*.c' -print | sort)
while IFS= read -r source; do
  relative=${source#"$lwip_dir/src/"}
  object_name=${relative//\//_}
  object="$lwip_test_build_dir/$object_name.o"
  cc -std=c11 -O2 -Wall -Wextra \
    -I"$project_dir/src/lwip" -I"$lwip_dir/src/include" \
    -c "$source" -o "$object"
  lwip_objects+=("$object")
done < <(find "$lwip_dir/src/core/ipv4" -maxdepth 1 -type f -name '*.c' -print | sort)

cc "${lwip_objects[@]}" -o "$lwip_test_build_dir/lwip_udp_selftest"
"$lwip_test_build_dir/lwip_udp_selftest"
