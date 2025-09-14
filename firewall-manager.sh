#!/bin/bash
set -euo pipefail

# =================================================================
#  NFTABLES Firewall Manager v3.10.0
# =================================================================
# - Strict default deny (INPUT/FORWARD/OUTPUT = drop; priority -10)
# - SSH auto-detect + brute-force limiter
# - Inbound allowlists (Panel/Inbounds) via menus
# - Outbound allowlists (System/Nodes/APIs) via menus
# - Blocklist loaded AFTER table creation, in CHUNKS, prune fallback
# - Docker bridges allowed in FORWARD
# - NEW: Dedicated boot unit firewall-manager.service loads our table,
#        independent of /etc/nftables.conf, so rules survive reboot.
# - ShellCheck clean for SC2181/SC2015 patterns
# - INPUT micro-optimization: drop saddr @blocked_ips only (daddr kept in FWD/OUT)
# =================================================================

# --- CONFIG ---
CONFIG_DIR="/etc/firewall_manager_nft"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"     # inbound TCP
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"     # inbound UDP
ALLOWED_NODE_TCP_FILE="$CONFIG_DIR/allowed_node_tcp_ports.conf" # outbound TCP
ALLOWED_NODE_UDP_FILE="$CONFIG_DIR/allowed_node_udp_ports.conf" # outbound UDP
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"
FIRST_RUN_STATE="$CONFIG_DIR/.system_prep_done"

# --- COLORS ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
press_enter_to_continue(){ echo ""; read -r -p "Press Enter to return..." < /dev/tty || true; }

ensure_config_dir(){
  mkdir -p "$CONFIG_DIR"
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
  port=$(
    ss -ltn 2>/dev/null | awk '/LISTEN/ {sub(/.*:/,"",$4); print $4}' |
    while read -r p; do ss -ltnp "sport = :$p" 2>/dev/null | grep -q sshd && { echo "$p"; break; }; done || true
  )
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

# Load the blocklist into nft set in chunks, prune if possible.
batch_load_blocklist() {
  local chunk=200
  local tmp_pruned; tmp_pruned=$(mktemp)

  # Generate pruned list with python; fall back to raw file if that fails/empty (SC2181-safe).
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
  # Also fall back if pruning produced nothing.
  if [ ! -s "$tmp_pruned" ]; then
    cp -f "$BLOCKED_IPS_FILE" "$tmp_pruned"
  fi

  # Deduplicate lines defensively.
  local tmp_unique; tmp_unique=$(mktemp)
  awk 'NF' "$tmp_pruned" | sort -u > "$tmp_unique"
  mv "$tmp_unique" "$tmp_pruned"

  # Clear existing elements to avoid duplicate-add errors.
  nft flush set inet firewall-manager blocked_ips >/dev/null 2>&1 || true

  # Load in chunks (do not let failures kill the script).
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

# ---------------- Docker detection ----------------
get_docker_ifaces(){
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '/^(docker0|br-)/{print $1}'
}

# ---------------- Boot persistence (dedicated unit) ----------------
ensure_boot_unit(){
  local unit="/etc/systemd/system/firewall-manager.service"
  # Create/refresh unit
  cat > "$unit" <<'UNIT'
[Unit]
Description=Firewall Manager (nftables) - load dedicated table
Documentation=https://github.com/Nima786/nftables-firewall-manager
After=nftables.service network-pre.target
Wants=network-pre.target
ConditionPathExists=/etc/nftables.d/firewall-manager.nft

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.d/firewall-manager.nft
ExecReload=/usr/sbin/nft -f /etc/nftables.d/firewall-manager.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  # Validate file parses before enabling the unit
  if nft -c -f /etc/nftables.d/firewall-manager.nft >/dev/null 2>&1; then
    systemctl enable --now firewall-manager.service >/dev/null 2>&1 || true
  fi
}

disable_boot_unit(){
  if systemctl list-unit-files | grep -q '^firewall-manager\.service'; then
    systemctl disable --now firewall-manager.service >/dev/null 2>&1 || true
  fi
}

# ---------------- Apply nft rules ----------------
apply_rules(){
  local no_pause=false; [[ "${1:-}" == "--no-pause" ]] && no_pause=true

  ensure_config_dir; ensure_blocklist_populated

  local ssh_port; ssh_port=$(detect_ssh_port); ensure_ssh_in_config

  local tcp_in udp_in tcp_node udp_node
  tcp_in=$(sort -un "$ALLOWED_TCP_PORTS_FILE" 2>/dev/null | grep -v -x "$ssh_port" | paste -sd, - || true)
  udp_in=$(sort -un "$ALLOWED_UDP_PORTS_FILE" 2>/dev/null | paste -sd, - || true)
  tcp_node=$(sort -un "$ALLOWED_NODE_TCP_FILE" 2>/dev/null | paste -sd, - || true)
  udp_node=$(sort -un "$ALLOWED_NODE_UDP_FILE" 2>/dev/null | paste -sd, - || true)

  declare -a DOCKER_IFACES=()
  mapfile -t DOCKER_IFACES < <(get_docker_ifaces || true) || true

  # Delete existing table only if it exists (SC2015-safe)
  if nft list table inet firewall-manager >/dev/null 2>&1; then
    nft delete table inet firewall-manager >/dev/null 2>&1 || true
  fi

  local tmp_rules; tmp_rules=$(mktemp)
  {
    echo "table inet firewall-manager {"
    echo "  set blocked_ips { type ipv4_addr; flags interval; }"
    echo "  set ssh_brute { type ipv4_addr; flags dynamic,timeout; timeout 5m; }"

    # INPUT
    echo "  chain input {"
    echo "    type filter hook input priority -10;"
    echo "    policy drop;"
    echo "    ct state { established,related } accept"
    echo "    iif lo accept"
    echo "    ct state invalid drop"
    echo "    icmp type { echo-request,echo-reply,destination-unreachable,time-exceeded,parameter-problem } accept"
    echo "    ip saddr @blocked_ips drop"    # keep source check only in INPUT
    echo "    ip saddr @ssh_brute limit rate over 4/minute burst 5 packets drop"
    echo "    tcp dport $ssh_port ct state new update @ssh_brute { ip saddr }"
    echo "    tcp dport $ssh_port accept"
    [[ -n "${tcp_in}" ]] && echo "    tcp dport { $tcp_in } accept"
    [[ -n "${udp_in}" ]] && echo "    udp dport { $udp_in } accept"
    echo "    log prefix \"[NFT DROP in] \" flags all counter drop"
    echo "  }"

    # FORWARD
    echo "  chain forward {"
    echo "    type filter hook forward priority -10;"
    echo "    policy drop;"
    echo "    ct state { established,related } accept"
    echo "    ct state invalid drop"
    echo "    ip saddr @blocked_ips drop"
    echo "    ip daddr @blocked_ips drop"
    echo "    udp dport 1-65535 limit rate over 200/second burst 5 packets drop"
    for ifc in "${DOCKER_IFACES[@]}"; do
      echo "    iifname \"$ifc\" accept"
      echo "    oifname \"$ifc\" accept"
    done
    echo "    udp dport { 53,123 } accept"
    echo "    tcp dport { 22 } accept"
    echo "    tcp dport { 80,443 } limit rate over 200/second burst 5 packets drop"
    echo "    tcp dport { 80,443 } accept"
    [[ -n "${tcp_node}" ]] && echo "    tcp dport { $tcp_node } accept"
    [[ -n "${udp_node}" ]] && echo "    udp dport { $udp_node } accept"
    echo "    log prefix \"[NFT DROP fwd] \" flags all counter drop"
    echo "  }"

    # OUTPUT
    echo "  chain output {"
    echo "    type filter hook output priority -10;"
    echo "    policy drop;"
    echo "    ct state { established,related } accept"
    echo "    ip saddr @blocked_ips drop"
    echo "    ip daddr @blocked_ips drop"
    echo "    udp dport 1-65535 limit rate over 200/second burst 5 packets drop"
    echo "    udp dport { 53,123 } accept"
    echo "    tcp dport { 22 } accept"
    echo "    tcp dport { 80,443 } limit rate over 200/second burst 5 packets drop"
    echo "    tcp dport { 80,443 } accept"
    [[ -n "${tcp_node}" ]] && echo "    tcp dport { $tcp_node } accept"
    [[ -n "${udp_node}" ]] && echo "    udp dport { $udp_node } accept"
    echo "    log prefix \"[NFT DROP out] \" flags all counter drop"
    echo "  }"

    echo "}"
  } > "$tmp_rules"

  if nft -f "$tmp_rules"; then
    # Load the blocklist elements AFTER the table exists
    if [ -s "$BLOCKED_IPS_FILE" ]; then
      echo -e "${YELLOW}Loading blocklist into set (chunked)...${NC}"
      batch_load_blocklist
    fi

    # Persist AFTER loading elements (so they survive reboot)
    mkdir -p /etc/nftables.d
    nft list table inet firewall-manager > /etc/nftables.d/firewall-manager.nft 2>/dev/null || true

    # Ensure dedicated boot unit is present and enabled (independent of /etc/nftables.conf)
    ensure_boot_unit

    echo -e "${GREEN}Firewall rules applied, persisted, and boot loader configured.${NC}"
  else
    echo -e "${RED}Failed to apply nftables ruleset!${NC}"
  fi

  rm -f "$tmp_rules" || true
  [[ "$no_pause" == false ]] && press_enter_to_continue
}

prompt_to_apply(){ apply_rules --no-pause; }

# ---------------- Port helpers ----------------
parse_and_process_ports(){
  local action="$1" proto_file="$2" input_ports="$3"; local -i count=0
  IFS=',' read -ra port_items <<< "$(echo "$input_ports" | tr ' ' ',')"
  for item in "${port_items[@]}"; do
    item=$(echo "$item" | xargs); [[ -z "$item" ]] && continue
    if [[ "$item" == *-* ]]; then
      local start_port end_port; start_port=${item%-*}; end_port=${item#*-}
      if [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ && "$start_port" -le "$end_port" ]]; then
        for ((port=start_port; port<=end_port; port++)); do
          if [[ "$action" == "add" ]] && ! grep -qx "$port" "$proto_file"; then echo "$port" >> "$proto_file"; ((count++)); fi
          if [[ "$action" == "remove" ]] &&  grep -qx "$port" "$proto_file"; then sed -i "/^${port}\$/d" "$proto_file"; ((count++)); fi
        done
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "add" ]] && ! grep -qx "$item" "$proto_file"; then echo "$item" >> "$proto_file"; ((count++))
      elif [[ "$action" == "remove" ]] && grep -qx "$item" "$proto_file"; then sed -i "/^${item}\$/d" "$proto_file"; ((count++)); fi
    fi
  done; echo "$count"
}

# ---------------- IP helpers ----------------
valid_ipv4_cidr(){
  local s="$1" ip mask
  ip=${s%%/*}; mask=${s#*/}
  [[ "$s" == "$ip" ]] && mask=""
  IFS='.' read -r a b c d <<<"$ip" || return 1
  for o in "$a" "$b" "$c" "$d"; do [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)) || return 1; done
  if [[ -n "$mask" ]]; then [[ "$mask" =~ ^[0-9]+$ ]] && ((mask>=0 && mask<=32)) || return 1; fi
  return 0
}
parse_and_process_ips(){
  local action="$1" input_items="$2"; local -i count=0
  input_items=$(echo "$input_items" | tr ' \n' ',')
  IFS=',' read -ra items <<< "$input_items"
  canonicalize_blocklist_file
  for raw in "${items[@]}"; do
    local item; item=$(echo "$raw" | xargs)
    [[ -z "$item" ]] && continue
    if ! valid_ipv4_cidr "$item"; then echo -e " -> ${RED}Invalid IPv4/CIDR: $item${NC}" >&2; continue; fi
    if [[ "$action" == "add" ]]; then
      if ! grep -qxF "$item" "$BLOCKED_IPS_FILE"; then echo "$item" >> "$BLOCKED_IPS_FILE"; canonicalize_blocklist_file; ((count++)); echo -e " -> ${GREEN}$item added.${NC}" >&2
      else echo -e " -> ${YELLOW}$item already present.${NC}" >&2; fi
    else
      if grep -qxF "$item" "$BLOCKED_IPS_FILE"; then
        local tmp; tmp=$(mktemp); grep -Fvx "$item" "$BLOCKED_IPS_FILE" > "$tmp" || true; mv "$tmp" "$BLOCKED_IPS_FILE"; canonicalize_blocklist_file
        ((count++)); echo -e " -> ${GREEN}$item removed.${NC}" >&2
      else echo -e " -> ${YELLOW}$item not found.${NC}" >&2; fi
    fi
  done
  echo "$count"
}

# ---------------- Views ----------------
view_rules(){
  clear
  echo -e "${YELLOW}--- Current 'inet firewall-manager' table ---${NC}"
  if nft list table inet firewall-manager >/dev/null 2>&1; then
    nft list table inet firewall-manager
    echo
    echo -e "${YELLOW}--- blocked_ips (show elements if any) ---${NC}"
    nft list set inet firewall-manager blocked_ips 2>/dev/null || true
  else
    echo "Table 'inet firewall-manager' not found. Use option 2 to apply rules."
  fi
  press_enter_to_continue
}

# ---------------- Menus ----------------
add_ports_interactive(){ local proto="$1" ; local proto_file
  [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
  clear; echo -e "${YELLOW}--- Add Allowed ${proto} Ports (INBOUND / Panel-Inbounds) ---${NC}"
  echo "Current ${proto}: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
  read -r -p "Enter ${proto} ports (e.g., 443 or 1000-2000, comma-separated): " input_ports < /dev/tty || true
  [[ -z "${input_ports:-}" ]] && return 0
  local changed; changed=$(parse_and_process_ports "add" "$proto_file" "$input_ports")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
}
remove_ports_interactive(){ local proto="$1" ; local proto_file
  [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
  clear; echo -e "${YELLOW}--- Remove Allowed ${proto} Ports (INBOUND / Panel-Inbounds) ---${NC}"
  echo "Current ${proto}: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
  read -r -p "Enter ${proto} ports to remove: " input_ports < /dev/tty || true
  [[ -z "${input_ports:-}" ]] && return 0
  local changed; changed=$(parse_and_process_ports "remove" "$proto_file" "$input_ports")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
}

add_node_ports_interactive(){ local proto="$1" ; local proto_file
  [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_NODE_TCP_FILE" || proto_file="$ALLOWED_NODE_UDP_FILE"
  clear; echo -e "${YELLOW}--- Add Outbound ${proto} Ports (System/Nodes/APIs) ---${NC}"
  echo "Current outbound ${proto}: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
  read -r -p "Enter ${proto} ports (e.g., 9012,9013 or 9000-9050): " input_ports < /dev/tty || true
  [[ -z "${input_ports:-}" ]] && return 0
  local changed; changed=$(parse_and_process_ports "add" "$proto_file" "$input_ports")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
}
remove_node_ports_interactive(){ local proto="$1" ; local proto_file
  [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_NODE_TCP_FILE" || proto_file="$ALLOWED_NODE_UDP_FILE"
  clear; echo -e "${YELLOW}--- Remove Outbound ${proto} Ports (System/Nodes/APIs) ---${NC}"
  echo "Current outbound ${proto}: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
  read -r -p "Enter ${proto} ports to remove: " input_ports < /dev/tty || true
  [[ -z "${input_ports:-}" ]] && return 0
  local changed; changed=$(parse_and_process_ports "remove" "$proto_file" "$input_ports")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
}

manage_node_ports_menu(){
  while true; do
    clear; echo "--- Allow Outbound Ports (For System/Nodes/APIs) ---"
    echo "TCP outbound: $(sort -n "$ALLOWED_NODE_TCP_FILE" 2>/dev/null | paste -s -d, || echo "None")"
    echo "UDP outbound: $(sort -n "$ALLOWED_NODE_UDP_FILE" 2>/dev/null | paste -s -d, || echo "None")"
    echo
    echo "1) Add Outbound TCP"
    echo "2) Remove Outbound TCP"
    echo "3) Add Outbound UDP"
    echo "4) Remove Outbound UDP"
    echo "5) Back"
    read -r -p "Choose an option: " choice < /dev/tty || true
    case "${choice:-}" in
      1) add_node_ports_interactive "TCP"; press_enter_to_continue ;;
      2) remove_node_ports_interactive "TCP"; press_enter_to_continue ;;
      3) add_node_ports_interactive "UDP"; press_enter_to_continue ;;
      4) remove_node_ports_interactive "UDP"; press_enter_to_continue ;;
      5) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

manage_ips_menu(){
  while true; do
    clear
    canonicalize_blocklist_file
    local total; total=$(wc -l < "$BLOCKED_IPS_FILE" 2>/dev/null || echo 0)
    echo "--- Manage Blocked IPs ---"
    echo "Total entries: ${total}"
    echo "Preview (first 50):"
    head -n 50 "$BLOCKED_IPS_FILE" 2>/dev/null | sed 's/^/  - /' || true
    echo
    echo "1) Add IP/CIDR (comma/space/newline separated)"
    echo "2) Remove IP/CIDR"
    echo "3) Show full list"
    echo "4) Back"
    read -r -p "Choose an option: " choice < /dev/tty || true

    local did_change=0
    case "${choice:-}" in
      1) read -r -p "Enter IPs/CIDRs to ADD: " ips < /dev/tty || true
         if [[ -n "${ips:-}" ]]; then local changed; changed=$(parse_and_process_ips "add" "$ips"); (( changed > 0 )) && did_change=1; fi ;;
      2) read -r -p "Enter IPs/CIDRs to REMOVE: " ips < /dev/tty || true
         if [[ -n "${ips:-}" ]]; then local changed; changed=$(parse_and_process_ips "remove" "$ips"); (( changed > 0 )) && did_change=1; fi ;;
      3) if command -v less >/dev/null 2>&1; then less -S "$BLOCKED_IPS_FILE" </dev/tty || true
         elif command -v more >/dev/null 2>&1; then more "$BLOCKED_IPS_FILE" </dev/tty || true
         else cat "$BLOCKED_IPS_FILE"; press_enter_to_continue; fi
         continue ;;
      4) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1; continue ;;
    esac

    if (( did_change )); then
      echo -e "${YELLOW}Applying firewall...${NC}"
      apply_rules --no-pause || true
    fi
    press_enter_to_continue
  done
}

manage_tcp_ports_menu(){
  while true; do
    clear; echo "--- Allow TCP Inbound Ports (For Panel/Inbounds) ---"
    echo "1) Add TCP Port(s)"; echo "2) Remove TCP Port(s)"; echo "3) Back"
    read -r -p "Choose an option: " choice < /dev/tty || true
    case "${choice:-}" in
      1) add_ports_interactive "TCP"; press_enter_to_continue ;;
      2) remove_ports_interactive "TCP"; press_enter_to_continue ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}
manage_udp_ports_menu(){
  while true; do
    clear; echo "--- Allow UDP Inbound Ports (For Panel/Inbounds) ---"
    echo "1) Add UDP Port(s)"; echo "2) Remove UDP Port(s)"; echo "3) Back"
    read -r -p "Choose an option: " choice < /dev/tty || true
    case "${choice:-}" in
      1) add_ports_interactive "UDP"; press_enter_to_continue ;;
      2) remove_ports_interactive "UDP"; press_enter_to_continue ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

view_rules_menu(){ view_rules; }

flush_rules(){
  clear
  read -r -p "ARE YOU SURE? This removes ONLY the firewall-manager table & config. (y/n): " confirm < /dev/tty || true
  if [[ "${confirm:-n}" =~ ^[yY]$ ]]; then
    if nft list table inet firewall-manager >/dev/null 2>&1; then
      nft delete table inet firewall-manager >/dev/null 2>&1 || true
    fi
    rm -f /etc/nftables.d/firewall-manager.nft || true
    rm -rf "$CONFIG_DIR" || true
    disable_boot_unit
    echo -e "${GREEN}Flushed our table and config. Other tables untouched.${NC}"
    ensure_config_dir
  else
    echo "Cancelled."
  fi
  press_enter_to_continue
}

uninstall_script(){
  clear; echo -e "${RED}--- UNINSTALL FIREWALL MANAGER ---${NC}"
  read -r -p "This deletes our table, config, and this script. Proceed? (y/n): " confirm < /dev/tty || true
  if [[ "${confirm:-n}" =~ ^[yY]$ ]]; then
    if nft list table inet firewall-manager >/dev/null 2>&1; then
      nft delete table inet firewall-manager >/dev/null 2>&1 || true
    fi
    rm -f /etc/nftables.d/firewall-manager.nft || true
    rm -rf "$CONFIG_DIR" || true
    disable_boot_unit
    echo -e "${GREEN}Firewall removed. Deleting script...${NC}"
    (sleep 1 && rm -f -- "$0") &
    exit 0
  else
    echo "Cancelled."
  fi
  press_enter_to_continue
}

# ---------------- Main ----------------
main_menu(){
  while true; do
    clear
    echo "=========================================="
    echo " NFTABLES FIREWALL MANAGER v3.10.0"
    echo "=========================================="
    echo "1) View Current Firewall Rules"
    echo "2) Apply Firewall Rules from Config"
    echo "3) Allow TCP Inbound Ports (For Panel/Inbounds)"
    echo "4) Allow UDP Inbound Ports (For Panel/Inbounds)"
    echo "5) Manage Blocked IPs"
    echo "6) Update IP Blocklist from Source"
    echo "7) Allow Outbound Ports (For System/Nodes/APIs)"
    echo "8) Flush All Rules & Reset Config"
    echo "9) Uninstall Firewall & Script"
    echo "0) Exit"
    echo "------------------------------------------"
    read -r -p "Choose an option: " choice < /dev/tty || true
    case "${choice:-}" in
      1) view_rules_menu ;;
      2) echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules ;;
      3) manage_tcp_ports_menu ;;
      4) manage_udp_ports_menu ;;
      5) manage_ips_menu ;;
      6) update_blocklist; press_enter_to_continue ;;   # keep menu alive
      7) manage_node_ports_menu ;;
      8) flush_rules ;;
      9) uninstall_script ;;
      0) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

# -------- Entry point --------
prepare_system
ensure_config_dir
ensure_ssh_in_config
ensure_blocklist_populated
main_menu
