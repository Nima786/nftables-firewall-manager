#!/bin/bash
set -euo pipefail

# =================================================================
#  NFTABLES Firewall Manager  – v8.2.3
# =================================================================
# - First-run: install deps (nftables, curl)
# - SSH autodetect & auto-allow
# - Manage TCP/UDP ports
# - Blocklist as nft set (flags interval) with overlap filtering
# - Docker-friendly FORWARD + destination drops
# - ICMP (ping + PMTU) allowed
# =================================================================

CONFIG_DIR="/etc/firewall_manager_nft"
TCP_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
UDP_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BL_FILE="$CONFIG_DIR/blocked_ips.conf"
BL_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"
FIRST_RUN_FLAG="$CONFIG_DIR/.system_prep_done"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
press_enter(){ echo ""; read -r -p "Press Enter to return..." < /dev/tty; }

ensure_cfg(){
  mkdir -p "$CONFIG_DIR"
  : >"${TCP_FILE}"      || true
  : >"${UDP_FILE}"      || true
  : >"${BL_FILE}"       || true
}

prepare_system(){
  ensure_cfg
  if [ -f "$FIRST_RUN_FLAG" ]; then
    echo "[+] First-run prep already done."
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  echo "[+] Installing dependencies..."
  apt-get update -y
  apt-get install -y nftables curl || true
  systemctl enable --now nftables >/dev/null 2>&1 || true
  touch "$FIRST_RUN_FLAG"
}

detect_ssh_port(){
  local p port=""
  port=$(
    ss -ltn 2>/dev/null | awk '/LISTEN/ && $4 ~ /:[0-9]+$/ { sub(/.*:/,"",$4); print $4 }' | sort -u |
    while read -r p; do ss -ltnp "sport = :$p" 2>/dev/null | grep -q sshd && { echo "$p"; break; }; done || true
  )
  if [[ -z "${port:-}" ]]; then
    port=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 || true)
  fi
  [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || port=22
  echo "$port"
}
ensure_ssh_allowed(){
  local sshp; sshp=$(detect_ssh_port)
  grep -qx "$sshp" "$TCP_FILE" || echo "$sshp" >> "$TCP_FILE"
}

# ---------- Blocklist handling ----------

canonicalize_bl(){
  # strip CR, comments, blanks; unique
  local tmp; tmp=$(mktemp)
  sed 's/\r$//' "$BL_FILE" 2>/dev/null \
  | awk '/^[[:space:]]*#/ {next} {gsub(/^[[:space:]]+|[[:space:]]+$/,""); if(length($0)) print $0}' \
  | sort -u > "$tmp"
  mv "$tmp" "$BL_FILE"
}

# Remove subnets that would conflict with an interval superset present.
# We purposely handle common supersets to avoid “conflicting intervals”.
filter_bl_for_interval(){
  canonicalize_bl
  local have_224 have_10 have_172 have_192168 have_10064 have_169254 have_19818
  grep -qx '224.0.0.0/4'     "$BL_FILE" && have_224=1     || have_224=0
  grep -qx '10.0.0.0/8'      "$BL_FILE" && have_10=1      || have_10=0
  grep -qx '172.16.0.0/12'   "$BL_FILE" && have_172=1     || have_172=0
  grep -qx '192.168.0.0/16'  "$BL_FILE" && have_192168=1  || have_192168=0
  grep -qx '100.64.0.0/10'   "$BL_FILE" && have_10064=1   || have_10064=0
  grep -qx '169.254.0.0/16'  "$BL_FILE" && have_169254=1  || have_169254=0
  grep -qx '198.18.0.0/15'   "$BL_FILE" && have_19818=1   || have_19818=0

  awk -v h224="$have_224" -v h10="$have_10" -v h172="$have_172" \
      -v h192168="$have_192168" -v h10064="$have_10064" \
      -v h169254="$have_169254" -v h19818="$have_19818" '
    function keep(l){
      if(h224    && l ~ /^(22[4-9]|23[0-9])\./)               return 0;   # 224-239.*
      if(h10     && l ~ /^10\./)                               return 0;   # 10/8
      if(h172    && l ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./)      return 0;   # 172.16-31
      if(h192168 && l ~ /^192\.168\./)                         return 0;   # 192.168/16
      if(h10064  && l ~ /^100\.(6[4-9]|[78][0-9]|9[01])\./)    return 0;   # 100.64-100.127
      if(h169254 && l ~ /^169\.254\./)                         return 0;   # 169.254/16
      if(h19818  && l ~ /^198\.(18|19)\./)                     return 0;   # 198.18/15
      return 1
    }
    /^[[:space:]]*#/ { next }
    NF { if (keep($0)) print $0 }
  ' "$BL_FILE" | sort -u
}

default_bl(){
  cat > "$BL_FILE" <<'EOL'
10.0.0.0/8
100.64.0.0/10
102.0.0.0/8
103.29.38.0/24
103.49.99.0/24
103.58.50.0/24
103.58.82.0/24
114.208.187.0/24
169.254.0.0/16
172.16.0.0/12
185.235.86.0/24
185.235.87.0/24
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
195.137.167.0/24
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
206.191.152.0/24
216.218.185.0/24
224.0.0.0/4
240.0.0.0/24
25.0.0.0/8
45.14.174.0/24
EOL
  canonicalize_bl
}

update_bl(){
  local tmp; tmp=$(mktemp)
  echo -e "${YELLOW}Downloading latest blocklist...${NC}"
  if curl -fsSL "$BL_URL" -o "$tmp"; then
    if [ -s "$tmp" ] && [ "$(wc -l < "$tmp")" -gt 10 ]; then
      sed -i 's/\r$//' "$tmp"
      awk '/^[[:space:]]*#/ {next} {gsub(/^[[:space:]]+|[[:space:]]+$/,""); if(length($0)) print $0}' "$tmp" \
        | sort -u > "$BL_FILE"
      rm -f "$tmp"
      echo -e "${GREEN}Blocklist updated.${NC}"
      return 0
    fi
  fi
  rm -f "$tmp" || true
  echo -e "${RED}Blocklist download failed or looked empty; keeping current file.${NC}"
  return 1
}

ensure_bl(){
  ensure_cfg
  canonicalize_bl
  if [ "$(wc -l < "$BL_FILE" 2>/dev/null || echo 0)" -eq 0 ]; then
    update_bl || default_bl
  fi
}

# ---------- Docker ifaces ----------
docker_ifaces(){
  ip -o link show 2>/dev/null | awk -F': ' '/^(docker0|br-)/{print $2}'
}

# ---------- Apply rules ----------
apply_rules(){
  local no_pause=false; [[ "${1:-}" == "--no-pause" ]] && no_pause=true
  [[ "$no_pause" == false ]] && clear

  ensure_cfg
  ensure_bl
  ensure_ssh_allowed

  local sshp; sshp=$(detect_ssh_port)

  # Read ports
  local tcp_list udp_list
  tcp_list=$({ sort -un "$TCP_FILE" 2>/dev/null | grep -vx "$sshp" || true; } | paste -sd',' -)
  udp_list=$({ sort -un "$UDP_FILE" 2>/dev/null || true; } | paste -sd',' -)

  # Filtered blocklist for interval set
  mapfile -t BL_CLEAN < <(filter_bl_for_interval) || true
  mapfile -t DOCK_IFS < <(docker_ifaces) || true

  # Nuke previous table to avoid "File exists"
  nft delete table inet firewall-manager >/dev/null 2>&1 || true

  # Compose comma list for set
  local bl_elems=""
  if ((${#BL_CLEAN[@]})); then
    for x in "${BL_CLEAN[@]}"; do bl_elems+="$x, "; done
    bl_elems="${bl_elems%, }"
  fi

  local f; f=$(mktemp)
  {
    echo "table inet firewall-manager {"
    echo "  set blocked_ips { type ipv4_addr; flags interval;"
    [[ -n "$bl_elems" ]] && echo "    elements = { $bl_elems }"
    echo "  }"
    echo "  chain input {"
    echo "    type filter hook input priority 0; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    iif lo accept"
    echo "    ct state invalid drop"
    # ICMP: ping + PMTU/errors
    echo "    icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept"
    echo "    ip saddr @blocked_ips drop"
    echo "    tcp dport $sshp accept"
    [[ -n "$tcp_list" ]] && echo "    tcp dport { $tcp_list } accept"
    [[ -n "$udp_list" ]] && echo "    udp dport { $udp_list } accept"
    echo "  }"
    echo "  chain forward {"
    echo "    type filter hook forward priority 0; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    ct state invalid drop"
    echo "    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept"
    echo "    ip daddr @blocked_ips drop"
    if ((${#DOCK_IFS[@]})); then
      for i in "${DOCK_IFS[@]}"; do
        echo "    iifname \"$i\" accept"
        echo "    oifname \"$i\" accept"
      done
    fi
    echo "  }"
    echo "  chain output {"
    echo "    type filter hook output priority 0; policy accept;"
    echo "    ip daddr @blocked_ips drop"
    echo "  }"
    echo "}"
  } > "$f"

  echo "[+] Building new nftables ruleset..."
  if nft -f "$f"; then
    echo -e "${GREEN}Applied.${NC}"
    echo -e "${YELLOW}Saving to /etc/nftables.conf ...${NC}"
    nft list ruleset > /etc/nftables.conf
    systemctl restart nftables >/dev/null 2>&1 || true
    echo -e "${GREEN}Persisted.${NC}"
  else
    echo -e "${RED}FATAL: Failed to apply nftables ruleset!${NC}"
    echo "Check for syntax errors or invalid entries."
  fi

  [[ "$no_pause" == false ]] && press_enter
}

prompt_apply(){ apply_rules --no-pause; }

# ---------- Port helpers (stdout only returns count) ----------
parse_ports(){
  local action="$1" file="$2" input="$3"
  local -i cnt=0; local sshp; sshp=$(detect_ssh_port)
  IFS=',' read -ra ITEMS <<<"$input"
  for it in "${ITEMS[@]}"; do
    it=$(echo "$it" | xargs)
    [[ -z "$it" ]] && continue
    if [[ "$it" == *-* ]]; then
      local a=${it%-*} b=${it#*-}
      if [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && $a -le $b ]]; then
        for ((p=a; p<=b; p++)); do
          if [[ "$action" == "remove" && "$file" == "$TCP_FILE" && "$p" == "$sshp" ]]; then continue; fi
          if [[ "$action" == "add"    && ! $(grep -qx "$p" "$file"; echo $?) -eq 0 ]]; then echo "$p" >> "$file"; ((cnt++))
          elif [[ "$action" == "remove" &&   $(grep -qx "$p" "$file"; echo $?) -eq 0 ]]; then sed -i "/^${p}\$/d" "$file"; ((cnt++)); fi
        done
        echo -e " -> ${GREEN}Range $it processed.${NC}" >&2
      else
        echo -e " -> ${RED}Invalid range: $it${NC}" >&2
      fi
    elif [[ "$it" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "remove" && "$file" == "$TCP_FILE" && "$it" == "$sshp" ]]; then
        echo -e " -> ${RED}Refusing to remove SSH ($sshp).${NC}" >&2; continue
      fi
      if [[ "$action" == "add" && "$file" == "$TCP_FILE" && "$it" == "$sshp" ]]; then
        echo -e " -> ${YELLOW}SSH is already auto-allowed.${NC}" >&2; continue
      fi
      if [[ "$action" == "add"    && ! $(grep -qx "$it" "$file"; echo $?) -eq 0 ]]; then echo "$it" >> "$file"; ((cnt++)); echo -e " -> ${GREEN}Port $it added.${NC}" >&2
      elif [[ "$action" == "remove" &&   $(grep -qx "$it" "$file"; echo $?) -eq 0 ]]; then sed -i "/^${it}\$/d" "$file"; ((cnt++)); echo -e " -> ${GREEN}Port $it removed.${NC}" >&2
      else echo -e " -> ${YELLOW}No change for $it.${NC}" >&2; fi
    else
      echo -e " -> ${RED}Invalid input: $it${NC}" >&2
    fi
  done
  printf '%s\n' "$cnt"
}

add_ports_ui(){
  local proto="$1" file; [[ "$proto" == "TCP" ]] && file="$TCP_FILE" || file="$UDP_FILE"
  clear; echo -e "${YELLOW}--- Add Allowed $proto Ports ---${NC}"
  echo "Current $proto: $(sort -n "$file" 2>/dev/null | paste -sd, - || echo none)"
  read -r -p "Enter $proto port(s) to add (e.g., 80,443 or 1000-2000): " in < /dev/tty
  [[ -z "$in" ]] && return 0
  local changed; changed=$(parse_ports add "$file" "$in")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
}
remove_ports_ui(){
  local proto="$1" file; [[ "$proto" == "TCP" ]] && file="$TCP_FILE" || file="$UDP_FILE"
  clear; echo -e "${YELLOW}--- Remove Allowed $proto Ports ---${NC}"
  echo "Current $proto: $(sort -n "$file" 2>/dev/null | paste -sd, - || echo none)"
  read -r -p "Enter $proto port(s) to remove: " in < /dev/tty
  [[ -z "$in" ]] && return 0
  local changed; changed=$(parse_ports remove "$file" "$in")
  (( changed > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; } || echo "No changes."
}

# ---------- IP list UI ----------
valid_ipv4_cidr(){
  local s="$1" ip=${1%%/*} mask=${1#*/}
  [[ "$s" == "$ip" ]] && mask=""
  IFS='.' read -r a b c d <<<"$ip" || return 1
  for o in "$a" "$b" "$c" "$d"; do [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)) || return 1; done
  if [[ -n "$mask" ]]; then [[ "$mask" =~ ^[0-9]+$ ]] && ((mask>=0 && mask<=32)) || return 1; fi
  return 0
}
edit_ips(){
  local action="$1" items="$2" count=0
  items=$(echo "$items" | tr ' \n' ','); IFS=',' read -ra ARR <<<"$items"
  canonicalize_bl
  for raw in "${ARR[@]}"; do
    local x; x=$(echo "$raw" | xargs); [[ -z "$x" ]] && continue
    if ! valid_ipv4_cidr "$x"; then echo -e " -> ${RED}Invalid IPv4/CIDR: $x${NC}" >&2; continue; fi
    if [[ "$action" == "add" ]]; then
      grep -qxF "$x" "$BL_FILE" || { echo "$x" >> "$BL_FILE"; ((count++)); }
    else
      if grep -qxF "$x" "$BL_FILE"; then sed -i "/^${x//./\\.}\$/d" "$BL_FILE"; ((count++)); fi
    fi
  done
  echo "$count"
}
ips_menu(){
  while true; do
    clear; canonicalize_bl
    local total; total=$(wc -l < "$BL_FILE" 2>/dev/null || echo 0)
    echo "--- Manage Blocked IPs ---"
    echo "Total entries: $total"
    head -n 50 "$BL_FILE" 2>/dev/null | sed 's/^/  - /' || true
    echo; echo "1) Add IP/CIDR"; echo "2) Remove IP/CIDR"; echo "3) Show full list"; echo "4) Back"
    read -r -p "Choose: " c < /dev/tty
    local ch=0
    case "$c" in
      1) read -r -p "Enter IPs/CIDRs to ADD: " in < /dev/tty; [[ -n "$in" ]] && ch=$(edit_ips add "$in") ;;
      2) read -r -p "Enter IPs/CIDRs to REMOVE: " in < /dev/tty; [[ -n "$in" ]] && ch=$(edit_ips remove "$in") ;;
      3) ${PAGER:-less} -S "$BL_FILE" </dev/tty || cat "$BL_FILE"; continue ;;
      4) break ;;
      *) echo -e "${RED}Invalid.${NC}"; sleep 1; continue ;;
    esac
    (( ch > 0 )) && { echo -e "${YELLOW}Applying firewall...${NC}"; apply_rules --no-pause; }
    press_enter
  done
}

view_rules(){ clear; echo -e "${YELLOW}--- Current Active NFTABLES Ruleset ---${NC}"; nft list ruleset; press_enter; }

flush_all(){
  clear
  read -r -p "This will FLUSH rules and RESET config. Continue? (y/n): " y < /dev/tty
  [[ "$y" =~ ^[yY]$ ]] || { echo "Cancelled."; press_enter; return; }
  nft flush ruleset
  echo "flush ruleset" > /etc/nftables.conf
  systemctl restart nftables || true
  rm -rf "$CONFIG_DIR"
  echo -e "${GREEN}All rules flushed and config reset.${NC}"
  press_enter
}

uninstall(){
  clear
  read -r -p "Uninstall firewall & script? (y/n): " y < /dev/tty
  [[ "$y" =~ ^[yY]$ ]] || { echo "Cancelled."; press_enter; return; }
  nft flush ruleset
  echo "flush ruleset" > /etc/nftables.conf
  systemctl restart nftables || true
  systemctl disable nftables >/dev/null 2>&1 || true
  rm -rf "$CONFIG_DIR"
  echo -e "${GREEN}Firewall removed. Script will self-delete.${NC}"
  (sleep 1 && rm -f -- "$0") &
  exit 0
}

initial_setup(){
  ensure_cfg
  ensure_ssh_allowed
  ensure_bl
  echo -e "${GREEN}Detected SSH on $(detect_ssh_port)/tcp; it will be allowed automatically.${NC}"
}

menu(){
  while true; do
    clear
    echo "==============================="
    echo " NFTABLES FIREWALL MANAGER v8.2.3"
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
    read -r -p "Choose an option: " ch < /dev/tty
    case "$ch" in
      1) view_rules ;;
      2) apply_rules ;;
      3) add_ports_ui "TCP"; press_enter ;;
      4) add_ports_ui "UDP"; press_enter ;;
      5) ips_menu ;;
      6) update_bl || true; press_enter ;;
      7) flush_all ;;
      8) uninstall ;;
      9) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

main(){
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Run as root (sudo).${NC}" >&2
    exit 1
  fi
  prepare_system
  initial_setup
  menu
}
main "$@"
