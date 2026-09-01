#!/usr/bin/env bash
set -euo pipefail

sunshine_host=${SUNSHINE_HOST:-127.0.0.1}
sunshine_tcp_ports=${SUNSHINE_TCP_PORTS:-"47984 47989 48010"}
sunshine_udp_ports=${SUNSHINE_UDP_PORTS:-"47998 47999 48000"}

state() {
  name=$1
  shift
  set +e
  "$@" >/dev/null 2>&1
  result=$?
  set -e
  if [ "$result" -eq 0 ]; then
    printf '%s=up\n' "$name"
  elif [ "$result" -eq 2 ]; then
    printf '%s=unknown\n' "$name"
  else
    printf '%s=down\n' "$name"
  fi
}

service_any() {
  for unit in "$@"; do
    if systemctl is-active --quiet "$unit"; then return 0; fi
  done
  return 1
}

nat_present() {
  if command -v nft >/dev/null 2>&1; then
    if rules=$(nft list ruleset 2>/dev/null); then
      printf '%s\n' "$rules" | grep -q 'wg-vita'
      return $?
    fi
  fi
  if command -v iptables >/dev/null 2>&1; then
    if rules=$(iptables -t nat -S 2>/dev/null); then
      printf '%s\n' "$rules" | grep -q 'wg-vita'
      return $?
    fi
  fi
  return 2
}

udp_listener() {
  ss -H -lun 2>/dev/null | awk '$5 ~ /:51820$/ { found=1 } END { exit !found }'
}

state playit service_any playitd.service playit.service
state tailscaled systemctl is-active --quiet tailscaled.service
state wireguard systemctl is-active --quiet wg-quick@wg-vita.service
state wg_interface ip link show wg-vita
state nat nat_present
state udp_51820 udp_listener

tcp_index=0
for port in $sunshine_tcp_ports; do
  tcp_index=$((tcp_index + 1))
  state "sunshine_tcp_${tcp_index}" nc -z -w 2 "$sunshine_host" "$port"
done

udp_index=0
for port in $sunshine_udp_ports; do
  udp_index=$((udp_index + 1))
  if nc -z -u -w 1 "$sunshine_host" "$port" >/dev/null 2>&1; then
    printf 'sunshine_udp_%s=probe_sent\n' "$udp_index"
  else
    printf 'sunshine_udp_%s=probe_failed\n' "$udp_index"
  fi
done

echo "external_relay=not_proven_without_external_client"
