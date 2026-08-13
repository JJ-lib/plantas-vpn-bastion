#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  printf 'ERROR: run as root\n' >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rule_source="$root/firewall/vpn-endpoint-monitor.nft"
unit_source="$root/systemd/vpn-endpoint-monitor-egress.service"
rule_target="/etc/nftables.d/vpn-endpoint-monitor.nft"
unit_target="/etc/systemd/system/vpn-endpoint-monitor-egress.service"

nft list table inet vpn_endpoint_monitor >/dev/null 2>&1 || nft add table inet vpn_endpoint_monitor
nft list table bridge vpn_endpoint_monitor_l2 >/dev/null 2>&1 || nft add table bridge vpn_endpoint_monitor_l2
nft -c -f "$rule_source"

install -d -o root -g root -m 0755 /etc/nftables.d
install -o root -g root -m 0640 "$rule_source" "$rule_target"
install -o root -g root -m 0644 "$unit_source" "$unit_target"
systemctl daemon-reload
systemctl enable vpn-endpoint-monitor-egress.service
systemctl start vpn-endpoint-monitor-egress.service

printf 'VPN endpoint monitor egress policy installed and active.\n'
