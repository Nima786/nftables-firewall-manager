#!/bin/bash
set -euo pipefail

# =================================================================
#  Interactive NFTABLES Firewall Manager - v8.2.1
# =================================================================
# - Applies only our table (no global flush)
# - Blocklist in a fast named set; overlaps removed
# - Elements added in chunks (no "elements = {}" in set decl)
# - Docker-aware FORWARD; ICMP allow for PMTU/diagnostics
# - Toggle blocklist enforcement ON/OFF
# - Flush All wipes rules + persistence + config dir
# =================================================================

# --- CONFIG ---
CONFIG_DIR="/etc/firewall_manager_nft"
ALLOWED_TCP="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS="$CONFIG_DIR/blocked_ips.conf"
ENABLE_BLOCKLIST_FLAG="$CONFIG_DIR/enable_blocklist"   # "1" (default) or "0"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"
FIRST_RUN_STATE="$CONFIG_DIR/.system_prep_done"

TABLE="firewall-manager"
SET_NAME="blocked_ips"          # ipv4 set name
CHUNK_SIZE=400                  # elements per add-element batch

# --- COLORS ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

press_enter(){ echo ""; read -r -p "Press Enter to return..." < /dev/tty; }

ensure_config_dir(){
  mkdir -p "$CONFIG_DIR"
  [[ -f "$ALLOWED_TCP" ]] || : > "$ALLOWED_TCP"
  [[ -f "$ALLOWED_UDP" ]] || : > "$ALLOWED_UDP"
  [[ -f "$BLOCKED_IPS" ]] || : > "$BLOCKED_IPS"
  [[ -f "$ENABLE_BLOCKLIST_FLAG" ]] || echo "1" > "$ENABLE_BLOCKLIST_FLAG"
}

prepare_system(){
  export DEBIAN_FRONTEND=noninteractive
  ensure_config_dir
  if [[ -f "$FIRST_RUN_STATE" ]]; then
    echo "[+] First-run system prep already done; skipping updates & installs."
    return
  fi
  echo "[+] First run: updating system & installing dependencies..."
  apt-get update -y
  apt-get -y upgrade || true
  apt-get install -y nftables curl
  systemctl enable nftables.service >/dev/null 2>&1 || true
  systemctl start  nftables.service  >/dev/null 2>&1 || true
  touch "$FIRST_RUN_STATE"
  echo "Initial system preparation complete."
}

detect_ssh_port(){
  local p=""
  p=$(
    ss -ltn 2>/dev/null | awk '/LISTEN/ && $4 ~ /:[0-9]+$/ {sub(/.*:/,"",$4); print $4}' | sort -u |
    while read -r x; do ss -ltnp "sport = :$x" 2>/dev/null | grep -q sshd && { echo "$x"; break; }; done || true
  )
  if [[ -z "${p:-}" ]]; then
    p=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 || true)
  fi
  [[ "$p" =~ ^[0-9]+$ ]] && ((p>=1 && p<=65535)) || p=22
  echo "$p"
}
ensure_ssh_in_config(){ local s; s=$(detect_ssh_port); grep -qx "$s" "$ALLOWED_TCP" || echo "$s" >> "$ALLOWED_TCP"; }

canonicalize_blocklist_file(){
  local tmp; tmp=$(mktemp)
  awk '
    { gsub(/\r/,"") }
    /^[[:space:]]*#/ { next }
    { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)) print $0 }
  ' "$BLOCKED_IPS" 2>/dev/null | sort -u > "$tmp"
  mv "$tmp" "$BLOCKED_IPS"
}

create_default_blocked_ips_fallback(){
  cat > "$BLOCKED_IPS" <<'EOL'
# Private/reserved & test nets
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
198.18.0.0/15
224.0.0.0/4
240.0.0.0/4
EOL
  # Call without () — this is a command invocation, not a function definition
  canonicalize_blocklist_file
}

update_blocklist(){
  echo -e "${YELLOW}Downloading latest blocklist...${NC}"
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    if [ -s "$tmp" ] && [ "$(wc -l < "$tmp")" -gt 10 ]; then
      sed -i 's/\r$//' "$tmp"
      awk '
        /^[[:space:]]*#/ { next }
        { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)) print $0 }
      ' "$tmp" | sort -u > "$BLOCKED_IPS"
      rm -f "$tmp"
      echo -e "${GREEN}Blocklist updated.${NC}"
      apply_rules --no-pause
      return 0
    fi
  fi
  echo -e "${RED}Blocklist download failed or too small. Keeping existing.${NC}"
  rm -f "$tmp" || true
  return 0
}

ensure_blocklist_populated(){
  canonicalize_blocklist_file
  local n; n=$(wc -l < "$BLOCKED_IPS" 2>/dev/null || echo 0)
  if [[ "${n:-0}" -eq 0 ]] ; then
    update_blocklist || create_default_blocked_ips_fallback
  fi
}

get_docker_ifaces(){ ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '/^(docker0|br-)/{print $1}'; }

# -- Remove overlaps so the set never complains
filter_blocklist_nonoverlap(){
  awk '
  function pow2(x) { return 2^x }
  function ip2int(a,b,c,d) { return (((a*256)+b)*256+c)*256+d }
  function parse(line,   ipmask,ip,n,oct,a,b,c,d,size,start,end) {
    split(line, ipmask, "/"); ip=ipmask[1]; n=ipmask[2]
    split(ip, oct, "."); a=oct[1]; b=oct[2]; c=oct[3]; d=oct[4]
    if (n == "" || n == 0) n=32
    size = pow2(32-n)
    start = int(ip2int(a,b,c,d)/size)*size
    end   = start + size - 1
    return start " " end " " n " " line
  }
  NF { print parse($0) }' \
  | sort -k1,1n -k3,3n \
  | awk '
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

create_table_and_chains(){
  nft list table inet "${TABLE}" >/dev/null 2>&1 && nft delete table inet "${TABLE}"

  local sshp tcp_list udp_list
  sshp=$(detect_ssh_port)
  ensure_ssh_in_config
  tcp_list=$( { sort -un "$ALLOWED_TCP" 2>/dev/null | grep -v -x "$sshp" || true; } | paste -sd, - )
  udp_list=$( { sort -un "$ALLOWED_UDP" 2>/dev/null || true; } | paste -sd, - )

  local tmp; tmp=$(mktemp)
  {
    echo "table inet ${TABLE} {"
    echo "  set ${SET_NAME} {"
    echo "    type ipv4_addr"
    echo "    flags interval"
    echo "  }"
    cat <<EOF
  chain input {
    type filter hook input priority 0; policy drop;
    ct state { established, related } accept
    iif lo accept
    ct state invalid drop
    icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept
    $( [[ "$(cat "$ENABLE_BLOCKLIST_FLAG")" = "1" ]] && echo "ip saddr @${SET_NAME} drop" )
    tcp dport ${sshp} accept
EOF
    [[ -n "$tcp_list" ]] && echo "    tcp dport { ${tcp_list} } accept"
    [[ -n "$udp_list" ]] && echo "    udp dport { ${udp_list} } accept"
    echo "  }"
    echo "  chain forward {"
    echo "    type filter hook forward priority 0; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    ct state invalid drop"
    echo "    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept"
    [[ "$(cat "$ENABLE_BLOCKLIST_FLAG")" = "1" ]] && echo "    ip daddr @${SET_NAME} drop"
    while read -r ifc; do
      [[ -z "$ifc" ]] && continue
      printf '    iifname "%s" accept\n' "$ifc"
      printf '    oifname "%s" accept\n' "$ifc"
    done < <(get_docker_ifaces || true)
    echo "  }"
    echo "  chain output {"
    echo "    type filter hook output priority 0; policy accept;"
    [[ "$(cat "$ENABLE_BLOCKLIST_FLAG")" = "1" ]] && echo "    ip daddr @${SET_NAME} drop"
    echo "  }"
    echo "}"
  } > "$tmp"

  if ! nft -f "$tmp" 2>/dev/null; then
    nft delete table inet "${TABLE}" 2>/dev/null || true
    nft -f "$tmp"
  fi
  rm -f "$tmp"
}

add_elements_to_set(){
  mapfile -t BL < <(awk 'NF&&$0!~/^#/' "$BLOCKED_IPS" 2>/dev/null | filter_blocklist_nonoverlap) || BL=()
  nft flush set inet "${TABLE}" "${SET_NAME}" 2>/dev/null || true
  [[ ${#BL[@]} -eq 0 ]] && return 0

  local total=${#BL[@]} i=0
  while (( i < total )); do
    local end=$(( i + CHUNK_SIZE )); (( end > total )) && end=$total
    local tmp; tmp=$(mktemp)
    {
      printf 'add element inet %s %s { ' "$TABLE" "$SET_NAME"
      local first=1
      for ((j=i; j<end; j++)); do
        if [[ $first -eq 1 ]]; then printf '%s' "${BL[j]}"; first=0; else printf ', %s' "${BL[j]}"; fi
      done
      printf ' }\n'
    } > "$tmp"

    if ! nft -f "$tmp" 2>/dev/null; then
      for ((j=i; j<end; j++)); do
        nft add element inet "$TABLE" "$SET_NAME" "{ ${BL[j]}; }" 2>/dev/null || true
      done
    fi
    rm -f "$tmp"
    i=$end
  done
}

apply_rules(){
  local no_pause=false; [[ "${1:-}" == "--no-pause" ]] && no_pause=true
  [[ "$no_pause" == false ]] && clear
  echo "[+] Building new nftables ruleset..."
  ensure_config_dir
  ensure_ssh_in_config
  ensure_blocklist_populated

  create_table_and_chains
  add_elements_to_set

  echo -e "\n${GREEN}Firewall configuration applied successfully!${NC}"
  echo -e "${YELLOW}Saving rules to /etc/nftables.conf...${NC}"
  nft list ruleset > /etc/nftables.conf
  systemctl restart nftables.service >/dev/null 2>&1 || true
  echo -e "${GREEN}Rules persisted.${NC}"
  [[ "$no_pause" == false ]] && press_enter
}

# ---------- port menus ----------
parse_ports(){
  local action="$1" file="$2" input="$3" changed=0
  IFS=',' read -ra items <<< "$input"
  for item in "${items[@]}"; do
    item=$(echo "$item" | xargs); [[ -z "$item" ]] && continue
    if [[ "$item" == *-* ]]; then
      local s=${item%-*} e=${item#*-}
      if [[ "$s" =~ ^[0-9]+$ && "$e" =~ ^[0-9]+$ && "$s" -le "$e" ]]; then
        for ((p=s; p<=e; p++)); do
          if [[ "$action" == "add" ]]; then
            grep -qx "$p" "$file" || { echo "$p" >> "$file"; ((changed++)); }
          else
            if grep -qx "$p" "$file"; then sed -i "/^${p}$/d" "$file"; ((changed++)); fi
          fi
        done
        echo -e " -> ${GREEN}Range $item processed.${NC}"
      else
        echo -e " -> ${RED}Invalid range: $item${NC}"
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "add" ]]; then
        grep -qx "$item" "$file" || { echo "$item" >> "$file"; ((changed++)); echo -e " -> ${GREEN}Port $item added.${NC}"; }
      else
        if grep -qx "$item" "$file"; then sed -i "/^${item}$/d" "$file"; ((changed++)); echo -e " -> ${GREEN}Port $item removed.${NC}"; else echo -e " -> ${YELLOW}Port $item not found.${NC}"; fi
      fi
    else
      echo -e " -> ${RED}Invalid: $item${NC}"
    fi
  done
  echo "$changed"
}
add_ports_menu(){
  local proto="$1" file; file="$ALLOWED_TCP"; [[ "$proto" == "UDP" ]] && file="$ALLOWED_UDP"
  clear; echo -e "${YELLOW}--- Add Allowed ${proto} Ports ---${NC}"
  echo "Current ${proto}: $(sort -n "$file" 2>/dev/null | paste -sd, - || echo "None")"
  read -r -p "Enter ${proto} port(s) to add (e.g., 80,443 or 1000-2000): " inp < /dev/tty
  [[ -z "$inp" ]] && return
  local ch; ch=$(parse_ports add "$file" "$inp")
  (( ch > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
  press_enter
}
remove_ports_menu(){
  local proto="$1" file; file="$ALLOWED_TCP"; [[ "$proto" == "UDP" ]] && file="$ALLOWED_UDP"
  clear; echo -e "${YELLOW}--- Remove Allowed ${proto} Ports ---${NC}"
  echo "Current ${proto}: $(sort -n "$file" 2>/dev/null | paste -sd, - || echo "None")"
  read -r -p "Enter ${proto} port(s) to remove: " inp < /dev/tty
  [[ -z "$inp" ]] && return
  local ch; ch=$(parse_ports remove "$file" "$inp")
  (( ch > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
  press_enter
}
manage_tcp_ports_menu(){
  while true; do
    clear; echo "--- Manage Allowed TCP Ports ---"
    echo "1) Add TCP Port(s)"; echo "2) Remove TCP Port(s)"; echo "3) Back"
    read -r -p "Choose an option: " c < /dev/tty
    case $c in
      1) add_ports_menu "TCP" ;;
      2) remove_ports_menu "TCP" ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}
manage_udp_ports_menu(){
  while true; do
    clear; echo "--- Manage Allowed UDP Ports ---"
    echo "1) Add UDP Port(s)"; echo "2) Remove UDP Port(s)"; echo "3) Back"
    read -r -p "Choose an option: " c < /dev/tty
    case $c in
      1) add_ports_menu "UDP" ;;
      2) remove_ports_menu "UDP" ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

# ---------- blocklist management ----------
valid_ipv4_cidr(){
  local s="$1" ip mask
  ip=${s%%/*}; mask=${s#*/}
  [[ "$s" == "$ip" ]] && mask=""
  IFS='.' read -r a b c d <<<"$ip" || return 1
  for o in "$a" "$b" "$c" "$d"; do [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)) || return 1; done
  if [[ -n "$mask" ]]; then [[ "$mask" =~ ^[0-9]+$ ]] && ((mask>=0 && mask<=32)) || return 1; fi
  return 0
}
parse_ips(){
  local action="$1" input="$2" changed=0
  input=$(echo "$input" | tr ' \n' ','); IFS=',' read -ra items <<< "$input"
  canonicalize_blocklist_file
  for raw in "${items[@]}"; do
    local x; x=$(echo "$raw" | xargs); [[ -z "$x" ]] && continue
    if ! valid_ipv4_cidr "$x"; then echo -e " -> ${RED}Invalid IPv4/CIDR: $x${NC}"; continue; fi
    if [[ "$action" == "add" ]]; then
      grep -qxF "$x" "$BLOCKED_IPS" || { echo "$x" >> "$BLOCKED_IPS"; ((changed++)); echo -e " -> ${GREEN}$x added.${NC}"; }
    else
      if grep -qxF "$x" "$BLOCKED_IPS"; then
        sed -i "\|^$x\$|d" "$BLOCKED_IPS"
        ((changed++)); echo -e " -> ${GREEN}$x removed.${NC}"
      else
        echo -e " -> ${YELLOW}$x not found.${NC}"
      fi
    fi
  done
  echo "$changed"
}
manage_ips_menu(){
  while true; do
    clear
    canonicalize_blocklist_file
    local total; total=$(wc -l < "$BLOCKED_IPS" 2>/dev/null || echo 0)
    echo "--- Manage Blocked IPs (set-based) ---"
    echo "Enforced: $( [[ "$(cat "$ENABLE_BLOCKLIST_FLAG")" = "1" ]] && echo ON || echo OFF )"
    echo "Total entries: ${total}"
    echo "Preview (first 50):"; head -n 50 "$BLOCKED_IPS" 2>/dev/null | sed 's/^/  - /' || true
    echo
    echo "1) Add IP/CIDR"; echo "2) Remove IP/CIDR"; echo "3) Show full list"
    echo "4) Toggle enforcement (ON/OFF)"; echo "5) Back"
    read -r -p "Choose an option: " choice < /dev/tty
    local changed=0
    case $choice in
      1) read -r -p "Enter IPs/CIDRs to ADD: " ips < /dev/tty; [[ -n "$ips" ]] && changed=$(parse_ips add "$ips") ;;
      2) read -r -p "Enter IPs/CIDRs to REMOVE: " ips < /dev/tty; [[ -n "$ips" ]] && changed=$(parse_ips remove "$ips") ;;
      3) ${PAGER:-less} "$BLOCKED_IPS" </dev/tty || true; continue ;;
      4) if [[ "$(cat "$ENABLE_BLOCKLIST_FLAG")" = "1" ]]; then echo "0" > "$ENABLE_BLOCKLIST_FLAG"; else echo "1" > "$ENABLE_BLOCKLIST_FLAG"; fi
         echo -e "${YELLOW}Enforcement toggled. Applying...${NC}"; apply_rules --no-pause; press_enter; continue ;;
      5) break ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1; continue ;;
    esac
    (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; }
    press_enter
  done
}

view_rules(){ clear; echo -e "${YELLOW}--- Current Active NFTABLES Ruleset ---${NC}"; nft list ruleset; press_enter; }

flush_rules(){
  clear
  read -r -p "ARE YOU SURE? This will flush all rules and reset the configuration. (y/n): " c < /dev/tty
  if [[ "$c" =~ ^[yY]$ ]]; then
    nft flush ruleset || true
    echo "flush ruleset" > /etc/nftables.conf
    systemctl restart nftables.service || true
    rm -rf "$CONFIG_DIR"
    ensure_config_dir; ensure_ssh_in_config
    echo -e "${GREEN}All rules flushed & config reset.${NC}"
  else
    echo "Operation cancelled."
  fi
  press_enter
}

uninstall_script(){
  clear; echo -e "${RED}--- UNINSTALL FIREWALL & SCRIPT ---${NC}"
  read -r -p "ARE YOU SURE you want to permanently delete the firewall and this script? (y/n): " c < /dev/tty
  if [[ "$c" =~ ^[yY]$ ]]; then
    nft flush ruleset || true
    echo "flush ruleset" > /etc/nftables.conf
    systemctl restart nftables.service || true
    rm -rf "$CONFIG_DIR"
    echo -e "${GREEN}Firewall removed. The script will self-destruct.${NC}"
    (sleep 1 && rm -f -- "$0") &; exit 0
  else
    echo "Operation cancelled."
  fi
  press_enter
}

initial_setup(){ ensure_config_dir; ensure_ssh_in_config; ensure_blocklist_populated; echo -e "${GREEN}Detected SSH on $(detect_ssh_port)/tcp; allowed automatically.${NC}"; }

main_menu(){
  while true; do
    clear
    echo "==============================="
    echo " NFTABLES FIREWALL MANAGER v8.2.1"
    echo "==============================="
    echo "1) View Current Firewall Rules"
    echo "2) Apply Firewall Rules from Config"
    echo "3) Manage Allowed TCP Ports"
    echo "4) Manage Allowed UDP Ports"
    echo "5) Manage Blocked IPs (set-based)"
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
      6) update_blocklist; press_enter ;;
      7) flush_rules ;;
      8) uninstall_script ;;
      9) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

main(){
  if [[ "$(id -u)" -ne 0 ]]; then echo -e "${RED}Run as root (sudo).${NC}" >&2; exit 1; fi
  prepare_system
  initial_setup
  main_menu
}
main "$@"
