#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
verifier="$project_dir/tests/verify_moonlight_vpk.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf -- "$fixture_root"' EXIT HUP INT TERM

make_tree() {
  destination=$1
  mkdir -p "$destination/sce_sys/livearea/contents" "$destination/assets"
  for entry in \
      sce_sys/param.sfo \
      eboot.bin \
      sce_sys/icon0.png \
      sce_sys/livearea/contents/bg.png \
      sce_sys/livearea/contents/startup.png \
      sce_sys/livearea/contents/template.xml \
      assets/nerdfont.ttf \
      THIRD_PARTY_NOTICES.md; do
    printf 'fixture:%s\n' "$entry" > "$destination/$entry"
  done
}

make_archive() {
  tree=$1
  archive=$2
  (cd "$tree" && zip -q -r "$archive" .)
}

expect_rejected() {
  name=$1
  archive=$2
  eboot=$3
  if "$verifier" "$archive" "$fixture_root/fake.elf" "$eboot" \
      >"$fixture_root/$name.out" 2>&1; then
    echo "FALHOU fixture VPK deveria ser rejeitada: $name" >&2
    return 1
  fi
}

printf 'not an elf\n' > "$fixture_root/fake.elf"

missing="$fixture_root/missing"
make_tree "$missing"
rm -- "$missing/sce_sys/param.sfo"
make_archive "$missing" "$fixture_root/missing.vpk"
expect_rejected missing "$fixture_root/missing.vpk" "$missing/eboot.bin"

private="$fixture_root/private"
make_tree "$private"
printf 'secret\n' > "$private/wg-private.key"
make_archive "$private" "$fixture_root/private.vpk"
expect_rejected private "$fixture_root/private.vpk" "$private/eboot.bin"

traversal="$fixture_root/traversal"
make_tree "$traversal"
printf 'bad\n' > "$traversal/safe-one"
make_archive "$traversal" "$fixture_root/traversal.vpk"
perl -pi -e 's#safe-one#../badone#g' "$fixture_root/traversal.vpk"
expect_rejected traversal "$fixture_root/traversal.vpk" "$traversal/eboot.bin"

absolute="$fixture_root/absolute"
make_tree "$absolute"
printf 'bad\n' > "$absolute/safe-path"
make_archive "$absolute" "$fixture_root/absolute.vpk"
perl -pi -e 's#safe-path#/absolute#g' "$fixture_root/absolute.vpk"
expect_rejected absolute "$fixture_root/absolute.vpk" "$absolute/eboot.bin"

duplicate="$fixture_root/duplicate"
make_tree "$duplicate"
printf 'one\n' > "$duplicate/dup-one"
printf 'two\n' > "$duplicate/dup-two"
make_archive "$duplicate" "$fixture_root/duplicate.vpk"
perl -pi -e 's#dup-(one|two)#dup-all#g' "$fixture_root/duplicate.vpk"
expect_rejected duplicate "$fixture_root/duplicate.vpk" "$duplicate/eboot.bin"

mismatch="$fixture_root/mismatch"
make_tree "$mismatch"
make_archive "$mismatch" "$fixture_root/mismatch.vpk"
printf 'different eboot\n' > "$fixture_root/other-eboot.bin"
expect_rejected mismatch "$fixture_root/mismatch.vpk" "$fixture_root/other-eboot.bin"

echo "OK: fixtures negativas do verificador VPK foram rejeitadas"
