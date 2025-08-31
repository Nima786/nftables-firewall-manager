#!/bin/bash
set -euo pipefail

# =================================================================
#  Interactive NFTABLES Firewall Manager - v8.3
# =================================================================
# - First-run ONLY: apt update/upgrade + install deps (nftables, curl)
# - Detect & auto-allow current SSH port
# - Manage TCP/UDP ports + IP blocklist (fast set-based lookups)
# - Docker-aware FORWARD rules
# - Netscan protection: drop blocked DEST at top of FORWARD
# - Allow ICMP (ping + PMTU)
# - Robust blocklist: interval set with overlap filtering
# =================================================================

# --- CONFIG ---
CONFIG_DIR="/etc/firewall_manager_nft"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"
FIRST_RUN_STATE="$CONFIG_DIR/.system_prep_done"

# --- COLORS ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

press_enter_to_continue(){ echo ""; read -r -p "Press Enter to return..." < /dev/tty; }

ensure_config_dir(){
  mkdir -p "$CONFIG_DIR"
  [ -f "$ALLOWED_TCP_PORTS_FILE" ] || : >"$ALLOWED_TCP_PORTS_FILE"
  [ -f "$ALLOWED_UDP_PORTS_FILE" ] || : >"$ALLOWED_UDP_PORTS_FILE"
  [ -f "$BLOCKED_IPS_FILE" ]      || : >"$BLOCKED_IPS_FILE"
}

prepare_system(){
  export DEBIAN_FRONTEND=noninteractive
  ensure_config_dir
  if [ -f "$FIRST_RUN_STATE" ]; then
    echo "[+] First-run system prep already done; skipping updates & installs."
    return 0
  fi
  echo "[+] First run detected: updating system and installing dependencies..."
  apt-get update -y
  apt-get -y upgrade || true
  apt-get install -y nftables curl
  systemctl enable nftables.service >/dev/null 2>&1 || true
  systemctl start  nftables.service  >/dev/null 2>&1 || true
  touch "$FIRST_RUN_STATE"
  echo "Initial system preparation complete."
}

detect_ssh_port(){
  local port=""
  port=$(
    ss -ltn 2>/dev/null | awk '/LISTEN/ && $4 ~ /:[0-9]+$/ {sub(/.*:/,"",$4); print $4}' | sort -u |
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

canonicalize_blocklist_file(){
  local tmp; tmp=$(mktemp)
  awk '
    { gsub(/\r/,"") }
    /^[[:space:]]*#/ { next }
    { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)) print $0 }
  ' "$BLOCKED_IPS_FILE" 2>/dev/null | sort -u > "$tmp"
  mv "$tmp" "$BLOCKED_IPS_FILE"
}
get_clean_blocklist(){ canonicalize_blocklist_file; cat "$BLOCKED_IPS_FILE"; }

create_default_blocked_ips_fallback(){
  cat > "$BLOCKED_IPS_FILE" << 'EOL'
# Private/reserved ranges (fallback)
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
  local is_initial="${1:-false}"
  if [[ "$is_initial" == true ]]; then
    echo -e "${YELLOW}Downloading latest blocklist (initial setup)...${NC}"
  else
    echo -e "${YELLOW}Downloading latest blocklist...${NC}"
  fi
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    if [ -s "$tmp" ] && [ "$(wc -l < "$tmp")" -gt 10 ]; then
      sed -i 's/\r$//' "$tmp"
      awk '
        /^[[:space:]]*#/ { next }
        { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)) print $0 }
      ' "$tmp" | sort -u > "$BLOCKED_IPS_FILE"
      rm -f "$tmp"
      echo -e "${GREEN}Blocklist updated.${NC}"
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

get_docker_ifaces(){
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '/^(docker0|br-)/{print $1}'
}

# ---- Filter out overlapping CIDRs (keep broader prefixes) ----
# Input: lines of a.b.c.d/n on stdin
# Output: non-overlapping CIDRs on stdout
filter_blocklist_nonoverlap() {
  awk '
  function pow2(x) { return 2^x }
  function ip2int(a,b,c,d) { return (((a*256)+b)*256+c)*256+d }
  function parse(line,   ip,mask,n,a,b,c,d,size,start,end) {
    split(line, ipmask, "/"); ip=ipmask[1]; n=ipmask[2]
    split(ip, oct, "."); a=oct[1]; b=oct[2]; c=oct[3]; d=oct[4]
    if (n == "") n=32
    size = pow2(32-n)
    start = int(ip2int(a,b,c,d)/size)*size
    end   = start + size - 1
    return start " " end " " n " " line
  }
  /^[[:space:]]*$/ { next }
  {
    print parse($0)
  }' \
  | sort -k1,1n -k3,3n \
  | awk '
    # keep an accepted list; skip a candidate if fully contained in any accepted interval
    {
      s=$1; e=$2; cidr=$4
      contained=0
      for (i=1;i<=cnt;i++){
        if (s>=S[i] && e<=E[i]) { contained=1; break }
      }
      if(!contained){ cnt++; S[cnt]=s; E[cnt]=e; C[cnt]=cidr }
    }
    END { for(i=1;i<=cnt;i++) print C[i] }
  '
}

apply_rules(){
  local no_pause=false; [[ "${1:-}" == "--no-pause" ]] && no_pause=true
  [[ "$no_pause" == false ]] && clear
  echo "[+] Building new nftables ruleset..."

  ensure_config_dir
  ensure_blocklist_populated

  local ssh_port; ssh_port=$(detect_ssh_port)
  ensure_ssh_in_config

  local tcp_ports udp_ports
  tcp_ports=$({ sort -un "$ALLOWED_TCP_PORTS_FILE" 2>/dev/null | grep -v -x "${ssh_port}" || true; } | tr '\n' ',' | sed 's/,$//')
  udp_ports=$({ sort -un "$ALLOWED_UDP_PORTS_FILE"  2>/dev/null || true; } | tr '\n' ',' | sed 's/,$//')

  declare -a BLOCKED_CLEAN=() BLOCKED_FILTERED=() DOCKER_IFACES=()
  mapfile -t BLOCKED_CLEAN   < <(get_clean_blocklist) || true
  mapfile -t DOCKER_IFACES   < <(get_docker_ifaces)   || true
  mapfile -t BLOCKED_FILTERED < <(printf '%s\n' "${BLOCKED_CLEAN[@]}" | filter_blocklist_nonoverlap) || true

  # Reserved/disjoint list (safe interval set)
  local -a RESERVED_ONLY=(10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4)

  nft list table inet firewall-manager >/dev/null 2>&1 && nft delete table inet firewall-manager

  local tmp_rules; tmp_rules=$(mktemp)
  {
    echo "table inet firewall-manager {"

    # blocked4: interval set (prefixes allowed) after filtering overlaps
    echo "  set blocked4 {"
    echo "    type ipv4_addr; flags interval;"
    if ((${#BLOCKED_FILTERED[@]})); then
      printf "    elements = { %s }\n" "$(printf '%s, ' "${BLOCKED_FILTERED[@]}" | sed 's/, $//')"
    else
      echo "    elements = { }"
    fi
    echo "  }"

    # reserved4: disjoint interval set
    echo "  set reserved4 {"
    echo "    type ipv4_addr; flags interval;"
    printf "    elements = { %s }\n" "$(printf '%s, ' "${RESERVED_ONLY[@]}" | sed 's/, $//')"
    echo "  }"

    cat <<EOF
  chain input {
    type filter hook input priority 0; policy drop;
    ct state { established, related } accept
    iif lo accept
    ct state invalid drop
    ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept
    ip saddr @blocked4 drop
    tcp dport ${ssh_port} accept
EOF
    [[ -n "$tcp_ports" ]] && printf '    tcp dport { %s } accept\n' "$tcp_ports"
    [[ -n "$udp_ports" ]] && printf '    udp dport { %s } accept\n' "$udp_ports"
    echo "  }"

    echo "  chain forward {"
    echo "    type filter hook forward priority 0; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    ct state invalid drop"
    echo "    ip daddr @blocked4 drop"
    if ((${#DOCKER_IFACES[@]})); then
      for ifc in "${DOCKER_IFACES[@]}"; do
        printf '    iifname "%s" accept\n' "$ifc"
        printf '    oifname "%s" accept\n' "$ifc"
      done
    fi
    echo "    ip saddr @blocked4 drop"
    echo "  }"

    echo "  chain output {"
    echo "    type filter hook output priority 0; policy accept;"
    echo "    ip daddr @reserved4 drop"
    echo "  }"

    echo "}"
  } > "$tmp_rules"

  if nft -f "$tmp_rules"; then
    echo -e "\n${GREEN}Firewall configuration applied successfully!${NC}"
    echo -e "${YELLOW}Saving rules to /etc/nftables.conf...${NC}"
    nft list ruleset > /etc/nftables.conf
    systemctl restart nftables.service >/dev/null 2>&1 || true
    echo -e "${GREEN}Rules persisted.${NC}"
  else
    echo -e "\n${RED}FATAL: Failed to apply nftables ruleset!${NC}"
    echo "Check for syntax errors or invalid entries in your config files."
  fi

  [[ "$no_pause" == false ]] && press_enter_to_continue
}
prompt_to_apply(){ apply_rules --no-pause; }

parse_and_process_ports(){
  local action="$1" proto_file="$2" input_ports="$3"
  local -i count=0
  local ssh_port; ssh_port=$(detect_ssh_port)
  IFS=',' read -ra port_items <<< "$input_ports"
  for item in "${port_items[@]}"; do
    item=$(echo "$item" | xargs)
    if [[ "$item" == *-* ]]; then
      local start_port end_port; start_port=${item%-*}; end_port=${item#*-}
      if [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ && "$start_port" -le "$end_port" ]]; then
        for ((port=start_port; port<=end_port; port++)); do
          if [[ "$action" == "remove" && "$port" == "$ssh_port" && "$proto_file" == "$ALLOWED_TCP_PORTS_FILE" ]]; then continue; fi
          if [[ "$action" == "add" ]] && ! grep -q "^${port}$" "$proto_file"; then echo "$port" >> "$proto_file"; ((count++));
          elif [[ "$action" == "remove" ]] && grep -q "^${port}$" "$proto_file"; then sed -i "/^${port}$/d" "$proto_file"; ((count++)); fi
        done
        echo -e " -> ${GREEN}Port range $item processed.${NC}" >&2
      else
        echo -e " -> ${RED}Invalid range: $item${NC}" >&2
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "remove" && "$item" == "$ssh_port" && "$proto_file" == "$ALLOWED_TCP_PORTS_FILE" ]]; then
        echo -e " -> ${RED}Safety: Cannot remove SSH port (${ssh_port}).${NC}" >&2; continue
      fi
      if [[ "$action" == "add" && "$item" == "$ssh_port" && "$proto_file" == "$ALLOWED_TCP_PORTS_FILE" ]]; then
        echo -e " -> ${YELLOW}SSH port is already allowed automatically.${NC}" >&2; continue
      fi
      if [[ "$action" == "add" ]] && ! grep -q "^${item}$" "$proto_file"; then echo "$item" >> "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item added.${NC}" >&2
      elif [[ "$action" == "add" ]]; then echo -e " -> ${YELLOW}Port $item already exists.${NC}" >&2
      elif [[ "$action" == "remove" ]] && grep -q "^${item}$" "$proto_file"; then sed -i "/^${item}$/d" "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item removed.${NC}" >&2
      else echo -e " -> ${YELLOW}Port $item not found.${NC}" >&2; fi
    elif [[ -n "$item" ]]; then echo -e " -> ${RED}Invalid input: $item${NC}" >&2; fi
  done
  printf '%s\n' "$count"
}

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
  local action="$1" input_items="$2"
  local -i count=0
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
  printf '%s\n' "$count"
}

add_ports_interactive(){ local proto="$1" ; local proto_file
  [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
  clear; echo -e "${YELLOW}--- Add Allowed ${proto} Ports ---${NC}"
  echo "Current ${proto} ports: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
  read -r -p "Enter ${proto} port(s) to add (e.g., 80,443 or 1000-2000): " input_ports < /dev/tty
  [[ -z "$input_ports" ]] && return 0
  local changed; changed=$(parse_and_process_ports "add" "$proto_file" "$input_ports")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
}
remove_ports_interactive(){ local proto="$1" ; local proto_file
  [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
  clear; echo -e "${YELLOW}--- Remove Allowed ${proto} Ports ---${NC}"
  echo "Current ${proto} ports: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
  read -r -p "Enter ${proto} port(s) to remove: " input_ports < /dev/tty
  [[ -z "$input_ports" ]] && return 0
  local changed; changed=$(parse_and_process_ports "remove" "$proto_file" "$input_ports")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
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
    read -r -p "Choose an option: " choice < /dev/tty

    local did_change=0
    case $choice in
      1) read -r -p "Enter IPs/CIDRs to ADD: " ips < /dev/tty
         if [[ -n "$ips" ]]; then local changed; changed=$(parse_and_process_ips "add" "$ips"); (( changed > 0 )) && did_change=1; fi ;;
      2) read -r -p "Enter IPs/CIDRs to REMOVE: " ips < /dev/tty
         if [[ -n "$ips" ]]; then local changed; changed=$(parse_and_process_ips "remove" "$ips"); (( changed > 0 )) && did_change=1; fi ;;
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

view_rules(){ clear; echo -e "${YELLOW}--- Current Active NFTABLES Ruleset ---${NC}"; nft list ruleset; press_enter_to_continue; }

manage_tcp_ports_menu(){
  while true; do
    clear; echo "--- Manage Allowed TCP Ports ---"
    echo "1) Add TCP Port(s)"; echo "2) Remove TCP Port(s)"; echo "3) Back"
    read -r -p "Choose an option: " choice < /dev/tty
    case $choice in
      1) add_ports_interactive "TCP"; press_enter_to_continue ;;
      2) remove_ports_interactive "TCP"; press_enter_to_continue ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}
manage_udp_ports_menu(){
  while true; do
    clear; echo "--- Manage Allowed UDP Ports ---"
    echo "1) Add UDP Port(s)"; echo "2) Remove UDP Port(s)"; echo "3) Back"
    read -r -p "Choose an option: " choice < /dev/tty
    case $choice in
      1) add_ports_interactive "UDP"; press_enter_to_continue ;;
      2) remove_ports_interactive "UDP"; press_enter_to_continue ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

flush_rules(){
  clear
  read -r -p "ARE YOU SURE? This will flush all rules and reset the configuration. (y/n): " confirm < /dev/tty
  if [[ "$confirm" =~ ^[yY]$ ]]; then
    echo "[+] Flushing ruleset..."
    nft flush ruleset
    echo "flush ruleset" > /etc/nftables.conf
    systemctl restart nftables.service || true
    echo -e "${GREEN}All rules flushed. The firewall is now open.${NC}"
    rm -rf "$CONFIG_DIR"
    initial_setup
  else
    echo "Operation cancelled."
  fi
  press_enter_to_continue
}

uninstall_script(){
  clear; echo -e "${RED}--- UNINSTALL FIREWALL & SCRIPT ---${NC}"
  read -r -p "ARE YOU SURE you want to permanently delete the firewall and this script? (y/n): " confirm < /dev/tty
  if [[ "$confirm" =~ ^[yY]$ ]]; then
    echo "[+] Flushing ruleset and disabling service..."
    nft flush ruleset
    echo "flush ruleset" > /etc/nftables.conf
    systemctl restart nftables.service || true
    systemctl disable nftables.service || true
    echo "[+] Deleting configuration directory..."
    rm -rf "$CONFIG_DIR"
    echo -e "${GREEN}Firewall has been removed. The script will now self-destruct.${NC}"
    (sleep 1 && rm -f -- "$0") &
    exit 0
  else
    echo "Operation cancelled."
  fi
  press_enter_to_continue
}

initial_setup(){
  ensure_config_dir
  local ssh_port; ssh_port=$(detect_ssh_port)
  echo -e "${GREEN}Detected SSH on ${ssh_port}/tcp; it will be allowed automatically.${NC}"
  ensure_ssh_in_config
  ensure_blocklist_populated
}

main_menu(){
  while true; do
    clear
    echo "==============================="
    echo " NFTABLES FIREWALL MANAGER v8.3"
    echo "==============================="
    echo "1) View Current Firewall Rules"
    echo "2) Apply Firewall Rules from Config"
    echo "3) Manage Allowed TCP Ports"
    echo "4) Manage Allowed UDP Ports"
    echo "5) Manage Blocked IPs"
    echo "6) Update IP Blocklist from Source"
    echo "7) Flush All Rules & Reset Config"
    echo "8) Uninstall Firewall & Script"
    echo "9) Exit"
    echo "-------------------------------"
    read -r -p "Choose an option: " choice < /dev/tty
    case $choice in
      1) view_rules ;;
      2) apply_rules ;;
      3) manage_tcp_ports_menu ;;
      4) manage_udp_ports_menu ;;
      5) manage_ips_menu ;;
      6) update_blocklist || true; press_enter_to_continue ;;
      7) flush_rules ;;
      8) uninstall_script ;;
      9) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

main(){
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2
    exit 1
  fi
  prepare_system
  initial_setup
  main_menu
}

main "$@"
