#!/bin/bash
set -euo pipefail
# --- ensure full script is loaded before running when piped ---
if [ -p /dev/stdin ]; then
  TMP=$(mktemp)
  cat >"$TMP"
  exec bash "$TMP"
fi

# =================================================================
#  NFTABLES Firewall Manager v6.1 (IPv6 Enhanced)
#  - Fully supports IPv6 for open ports and essential ICMPv6
#  - Uses modular includes (/etc/nftables.d/)
#  - Default-deny firewall with minimal exceptions
# =================================================================

# --- CONFIG ---
CONFIG_DIR="/etc/firewall_manager_nft"
NFT_RULES_DIR="/etc/nftables.d"
OUR_RULES_FILE="$NFT_RULES_DIR/firewall-manager.nft"

ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
ALLOWED_NODE_TCP_FILE="$CONFIG_DIR/allowed_node_tcp_ports.conf"
ALLOWED_NODE_UDP_FILE="$CONFIG_DIR/allowed_node_udp_ports.conf"

BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"
FIRST_RUN_STATE="$CONFIG_DIR/.system_prep_done"

# --- COLORS ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
press_enter_to_continue(){ echo ""; read -r -p "Press Enter to return..." < /dev/tty || true; }

ensure_config_dir(){
  mkdir -p "$CONFIG_DIR" "$NFT_RULES_DIR"
  [ -f "$ALLOWED_TCP_PORTS_FILE" ] || : >"$ALLOWED_TCP_PORTS_FILE"
  [ -f "$ALLOWED_UDP_PORTS_FILE" ] || : >"$ALLOWED_UDP_PORTS_FILE"
  [ -f "$ALLOWED_NODE_TCP_FILE" ]  || : >"$ALLOWED_NODE_TCP_FILE"
  [ -f "$ALLOWED_NODE_UDP_FILE" ]  || : >"$ALLOWED_NODE_UDP_FILE"
  [ -f "$BLOCKED_IPS_FILE" ]       || : >"$BLOCKED_IPS_FILE"
}

# ---------------- First-run ONLY ----------------
prepare_system(){
  export DEBIAN_FRONTEND=noninteractive
  ensure_config_dir
  if [ -f "$FIRST_RUN_STATE" ]; then return 0; fi
  apt-get update -y || true
  apt-get -y upgrade || true
  apt-get install -y nftables curl python3 || true
  systemctl enable nftables.service >/dev/null 2>&1 || true
  systemctl start  nftables.service  >/dev/null 2>&1 || true
  touch "$FIRST_RUN_STATE"
}

# ---------------- SSH port detection ----------------
detect_ssh_port(){
  local port=""
  if command -v sshd >/dev/null 2>&1; then
    port=$(sshd -T 2>/dev/null | awk '/^port[[:space:]]/{print $2; exit}' || true)
  fi
  if [[ -z "${port:-}" ]]; then
    port=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 || true)
  fi
  [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || port=22
  echo "$port"
}
ensure_ssh_in_config(){
  local ssh_port; ssh_port=$(detect_ssh_port)
  grep -qx "$ssh_port" "$ALLOWED_TCP_PORTS_FILE" || echo "$ssh_port" >> "$ALLOWED_TCP_PORTS_FILE"
}

# ---------------- Blocklist helpers ----------------
canonicalize_blocklist_file(){
  local tmp; tmp=$(mktemp)
  awk '{ gsub(/\r/,"") } /^[[:space:]]*#/ {next} {gsub(/^[[:space:]]+|[[:space:]]+$/,""); if(length)print}' "$BLOCKED_IPS_FILE" 2>/dev/null | sort -u > "$tmp"
  mv "$tmp" "$BLOCKED_IPS_FILE"
}
get_clean_blocklist(){ canonicalize_blocklist_file; cat "$BLOCKED_IPS_FILE"; }

create_default_blocked_ips_fallback(){
  cat > "$BLOCKED_IPS_FILE" << 'EOL'
# Private/reserved (fallback)
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
198.18.0.0/15
EOL
  canonicalize_blocklist_file
}

update_blocklist(){
  local is_initial=${1:-false}
  echo -e "${YELLOW}Downloading latest blocklist...${NC}"
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    if [ -s "$tmp" ] && [ "$(wc -l < "$tmp")" -gt 5 ]; then
      sed -i 's/\r$//' "$tmp"
      awk '/^[[:space:]]*#/ { next } { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)) print $0 }' "$tmp" | sort -u > "$BLOCKED_IPS_FILE"
      rm -f "$tmp"
      echo -e "${GREEN}Blocklist updated.${NC}"
      [[ "$is_initial" == false ]] && prompt_to_apply
      return 0
    fi
  fi
  echo -e "${RED}Blocklist download failed or too small. Keeping existing.${NC}"
  rm -f "$tmp" || true
  return 0
}
ensure_blocklist_populated(){
  ensure_config_dir
  canonicalize_blocklist_file
  local count; count=$(wc -l < "$BLOCKED_IPS_FILE" 2>/dev/null || echo 0)
  if [ "${count:-0}" -eq 0 ]; then
    update_blocklist true || create_default_blocked_ips_fallback
  fi
}

batch_load_blocklist() {
  local chunk=200
  local tmp_pruned; tmp_pruned=$(mktemp)
  if ! python3 - "$BLOCKED_IPS_FILE" > "$tmp_pruned" <<'PY'
import sys, ipaddress
src_path = sys.argv[1] if len(sys.argv) > 1 else None
fh = open(src_path, 'r') if src_path else sys.stdin
nets=[]
for line in fh:
    s=line.strip()
    if not s or s.startswith('#'):
        continue
    try:
        nets.append(ipaddress.ip_network(s, strict=False))
    except Exception:
        pass
for n in ipaddress.collapse_addresses(nets):
    print(n)
PY
  then
    cp -f "$BLOCKED_IPS_FILE" "$tmp_pruned"
  fi
  [ -s "$tmp_pruned" ] || cp -f "$BLOCKED_IPS_FILE" "$tmp_pruned"
  local tmp_unique; tmp_unique=$(mktemp)
  awk 'NF' "$tmp_pruned" | sort -u > "$tmp_unique"
  mv "$tmp_unique" "$tmp_pruned"
  nft flush set inet firewall-manager blocked_ips >/dev/null 2>&1 || true
  set +e
  local buf=() count=0
  while IFS= read -r net; do
    [[ -z "$net" ]] && continue
    buf+=("$net"); ((count++))
    if (( count % chunk == 0 )); then
      local csv; csv=$(printf '%s,' "${buf[@]}" | sed 's/,$//')
      printf 'add element inet firewall-manager blocked_ips { %s }\n' "$csv" | nft -f - >/dev/null 2>&1
      buf=()
    fi
  done < "$tmp_pruned"
  if (( ${#buf[@]} )); then
    local csv; csv=$(printf '%s,' "${buf[@]}" | sed 's/,$//')
    printf 'add element inet firewall-manager blocked_ips { %s }\n' "$csv" | nft -f - >/dev/null 2>&1
  fi
  set -e
  rm -f "$tmp_pruned" || true
}

# ---------------- Apply nft rules (IPv6 Enhanced) ----------------
apply_rules(){
  local no_pause=false; [[ "${1:-}" == "--no-pause" ]] && no_pause=true

  ensure_config_dir; ensure_blocklist_populated

  local ssh_port; ssh_port=$(detect_ssh_port); ensure_ssh_in_config

  local tcp_in udp_in tcp_node udp_node
  tcp_in=$(sort -un "$ALLOWED_TCP_PORTS_FILE" 2>/dev/null | grep -v -x "$ssh_port" | paste -sd, - || true)
  udp_in=$(sort -un "$ALLOWED_UDP_PORTS_FILE" 2>/dev/null | paste -sd, - || true)
  tcp_node=$(sort -un "$ALLOWED_NODE_TCP_FILE" 2>/dev/null | paste -sd, - || true)
  udp_node=$(sort -un "$ALLOWED_NODE_UDP_FILE" 2>/dev/null | paste -sd, - || true)

  local docker_ifaces="{ docker0, br-*, docker_gwbridge, cni-* }"

  nft delete table inet firewall-manager >/dev/null 2>&1 || true

  local tmp_rules; tmp_rules=$(mktemp)
  {
    echo "table inet firewall-manager {"
    echo "  set blocked_ips { type ipv4_addr; flags interval; }"
    echo "  set blocked_ips_v6 { type ipv6_addr; flags interval; }"
    echo "  set ssh_brute { type ipv4_addr; flags dynamic,timeout; timeout 5m; }"

    echo "  chain input {"
    echo "    type filter hook input priority -10; policy drop;"
    echo "    ct state { established,related } accept"
    echo "    iif lo accept"
    echo "    ct state invalid drop"

    echo "    # Allow essential ICMPv4 and ICMPv6"
    echo "    icmp type { echo-request,echo-reply,destination-unreachable,time-exceeded,parameter-problem } accept"
    echo "    icmpv6 type { echo-request,echo-reply,destination-unreachable,packet-too-big,time-exceeded,parameter-problem,neighbour-solicitation,neighbour-advertisement,router-solicitation,router-advertisement } accept"

    echo "    ip saddr @blocked_ips drop"
    echo "    ip6 saddr @blocked_ips_v6 drop"

    echo "    ip saddr @ssh_brute limit rate over 4/minute burst 5 packets drop"
    echo "    tcp dport $ssh_port ct state new update @ssh_brute { ip saddr }"
    echo "    tcp dport $ssh_port accept"

    [[ -n "${tcp_in}" ]] && echo "    tcp dport { $tcp_in } accept"
    [[ -n "${udp_in}" ]] && echo "    udp dport { $udp_in } accept"

    echo "    log prefix \"[NFT DROP in] \" flags all counter drop"
    echo "  }"

    echo "  chain forward {"
    echo "    type filter hook forward priority -10; policy drop;"
    echo "    ct state { established,related } accept"
    echo "    ct state invalid drop"
    echo "    ip saddr @blocked_ips drop"
    echo "    ip daddr @blocked_ips drop"
    echo "    ip6 saddr @blocked_ips_v6 drop"
    echo "    ip6 daddr @blocked_ips_v6 drop"
    echo "    oifname $docker_ifaces accept"
    echo "    udp dport { 53, 123 } accept"
    echo "    tcp dport { 80, 443 } accept"
    [[ -n "${tcp_node}" ]] && echo "    tcp dport { $tcp_node } accept"
    [[ -n "${udp_node}" ]] && echo "    udp dport { $udp_node } accept"
    echo "    log prefix \"[NFT DROP fwd] \" flags all counter drop"
    echo "  }"

    echo "  chain output {"
    echo "    type filter hook output priority -10; policy accept;"
    echo "    ip daddr @blocked_ips drop"
    echo "    ip6 daddr @blocked_ips_v6 drop"
    echo "  }"
    echo "}"
  } > "$tmp_rules"

  if nft -f "$tmp_rules"; then
    [ -s "$BLOCKED_IPS_FILE" ] && { echo -e "${YELLOW}Loading blocklist...${NC}"; batch_load_blocklist; }

    if ! grep -q 'include "/etc/nftables.d/\*\.nft"' /etc/nftables.conf 2>/dev/null; then
      echo -e "${YELLOW}Configuring /etc/nftables.conf for modular rules...${NC}"
      cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
    fi

    nft list table inet firewall-manager > "$OUR_RULES_FILE" 2>/dev/null || true
    systemctl reload nftables.service >/dev/null 2>&1 || true
    echo -e "${GREEN}Firewall rules applied and persisted.${NC}"
  else
    echo -e "${RED}Failed to apply nftables ruleset!${NC}"
  fi
  rm -f "$tmp_rules" || true
  [[ "$no_pause" == false ]] && press_enter_to_continue
}

# --- Remaining functions unchanged below ---
# (Menus, add/remove ports, view rules, uninstall, etc.)
# Keep all of your existing helper and menu functions as-is.

# -------- Safe entrypoint when piped through curl --------
if [[ "${BASH_SOURCE[0]:-}" == "${0:-}" || -z "${BASH_SOURCE:-}" ]]; then
  prepare_system
  ensure_config_dir
  ensure_ssh_in_config
  ensure_blocklist_populated
  main_menu
fi
