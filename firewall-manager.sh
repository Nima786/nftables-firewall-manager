#!/bin/bash
set -euo pipefail

# ==========================================================
#  NFTABLES FIREWALL MANAGER  v8.4
#  - Debian/Ubuntu
#  - nftables + blocklist set (interval)
#  - Ports/Blocklist stored under /etc/firewall_manager_nft
# ==========================================================

# -------------------- Paths & constants -------------------
CONFIG_DIR="/etc/firewall_manager_nft"
TCP_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
UDP_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BL_FILE="$CONFIG_DIR/blocked_ips.conf"
FIRST_RUN_FLAG="$CONFIG_DIR/.prep_done"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"
TABLE="firewall-manager"
SETNAME="blocked_ips"

# -------------------- Colors ------------------------------
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

pause(){ echo; read -r -p "Press Enter to return..." < /dev/tty; }

# -------------------- Helpers -----------------------------
ensure_dirs(){
  mkdir -p "$CONFIG_DIR"
  : >"$TCP_FILE" || true
  : >"$UDP_FILE" || true
  : >"$BL_FILE"  || true
}

prepare_system(){
  ensure_dirs
  if [[ -f "$FIRST_RUN_FLAG" ]]; then
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nftables curl
  systemctl enable nftables.service >/dev/null 2>&1 || true
  systemctl start  nftables.service  >/dev/null 2>&1 || true
  touch "$FIRST_RUN_FLAG"
}

detect_ssh_port(){
  # Try “ss + process” first
  local p
  p=$(
    ss -ltnp 2>/dev/null \
    | awk '/sshd/ && /LISTEN/ { sub(/.*:/,"",$4); print $4 }' \
    | sort -u | head -n1
  ) || true
  # Fallback to config parse
  if [[ -z "${p:-}" ]]; then
    p=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1) || true
  fi
  [[ "$p" =~ ^[0-9]+$ ]] && ((p>=1 && p<=65535)) || p=22
  echo "$p"
}

ensure_ssh_in_tcp(){
  local sp; sp=$(detect_ssh_port)
  grep -qx "$sp" "$TCP_FILE" || echo "$sp" >> "$TCP_FILE"
}

# --- sanitize a list file: strip comments/blank, uniq, sort
canon_file(){
  local f="$1" tmp; tmp=$(mktemp)
  awk '
    { gsub(/\r/,"") }
    /^[[:space:]]*#/ { next }
    { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length) print }
  ' "$f" 2>/dev/null | sort -Vu > "$tmp"
  mv "$tmp" "$f"
}

# --- default blocklist if download not available
write_default_blocklist(){
  cat > "$BL_FILE" <<'EOF'
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
198.18.0.0/15
25.0.0.0/8
45.14.174.0/24
102.0.0.0/8
103.29.38.0/24
103.49.99.0/24
103.58.50.0/24
103.58.82.0/24
114.208.187.0/24
185.235.86.0/24
185.235.87.0/24
192.0.0.0/24
192.88.99.0/24
195.137.167.0/24
206.191.152.0/24
216.218.185.0/24
224.0.0.0/4
240.0.0.0/24
EOF
  canon_file "$BL_FILE"
}

update_blocklist(){
  echo -e "${Y}Downloading latest blocklist...${N}"
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    if [[ -s "$tmp" ]] && [[ "$(wc -l < "$tmp")" -ge 10 ]]; then
      awk '
        /^[[:space:]]*#/ { next }
        { gsub(/\r/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length) print }
      ' "$tmp" | sort -Vu > "$BL_FILE"
      rm -f "$tmp"
      echo -e "${G}Blocklist updated.${N}"
      return 0
    fi
  fi
  rm -f "$tmp" || true
  if [[ ! -s "$BL_FILE" ]]; then
    echo -e "${Y}Using fallback blocklist.${N}"
    write_default_blocklist
  else
    echo -e "${Y}Keeping existing blocklist.${N}"
  fi
}

need_blocklist_ready(){
  canon_file "$BL_FILE"
  if [[ ! -s "$BL_FILE" ]]; then
    update_blocklist
  fi
}

docker_ifaces(){
  ip -o link show 2>/dev/null \
  | awk -F': ' '{print $2}' \
  | awk '/^(docker0|br-)/{print $1}'
}

# Join file lines by comma
join_file_csv(){
  local f="$1"
  awk 'NF{print $0}' "$f" 2>/dev/null | paste -sd, -
}

# -------------------- Apply rules -------------------------
apply_rules(){
  clear
  echo "[+] Building new nftables ruleset..."

  ensure_dirs
  ensure_ssh_in_tcp
  need_blocklist_ready
  canon_file "$TCP_FILE"
  canon_file "$UDP_FILE"

  local ssh_port tcp_csv udp_csv
  ssh_port=$(detect_ssh_port)

  # Filter SSH out of the visible set so we don't duplicate that line
  tcp_csv=$(
    grep -v -x "$ssh_port" "$TCP_FILE" 2>/dev/null | awk 'NF' | sort -un | paste -sd, - || true
  )
  udp_csv=$(
    awk 'NF' "$UDP_FILE" 2>/dev/null | sort -un | paste -sd, - || true
  )

  local blocked_csv
  blocked_csv=$(join_file_csv "$BL_FILE")

  # nuke table if it exists, then build fresh config in one shot
 if nft list table inet "$TABLE" >/dev/null 2>&1; then
  nft delete table inet "$TABLE"
fi

  local tmp; tmp=$(mktemp)
  {
    echo "table inet $TABLE {"
    echo "  set $SETNAME {"
    echo "    type ipv4_addr"
    echo "    flags interval"
    if [[ -n "$blocked_csv" ]]; then
      echo "    elements = { $blocked_csv }"
    fi
    echo "  }"
    echo
    echo "  chain input {"
    echo "    type filter hook input priority 0; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    iif lo accept"
    echo "    ct state invalid drop"
    echo "    icmp type { echo-reply, destination-unreachable, echo-request, time-exceeded, parameter-problem } accept"
    echo "    ip saddr @$SETNAME drop"
    echo "    tcp dport $ssh_port accept"
    [[ -n "$tcp_csv" ]] && echo "    tcp dport { $tcp_csv } accept"
    [[ -n "$udp_csv" ]] && echo "    udp dport { $udp_csv } accept"
    echo "  }"
    echo
    echo "  chain forward {"
    echo "    type filter hook forward priority 0; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    ct state invalid drop"
    echo "    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept"
    echo "    ip daddr @$SETNAME drop"
    # Allow docker bridges if present
    while read -r br; do
      [[ -n "$br" ]] || continue
      echo "    iifname \"$br\" accept"
      echo "    oifname \"$br\" accept"
    done < <(docker_ifaces)
    echo "  }"
    echo
    echo "  chain output {"
    echo "    type filter hook output priority 0; policy accept;"
    echo "    ip daddr @$SETNAME drop"
    echo "  }"
    echo "}"
  } > "$tmp"

  if nft -f "$tmp"; then
    echo -e "${G}Applied.${N}"
    echo -e "${Y}Saving to /etc/nftables.conf ...${N}"
    nft list ruleset > /etc/nftables.conf
    systemctl restart nftables.service >/dev/null 2>&1 || true
    echo -e "${G}Persisted.${N}"
  else
    echo -e "${R}FATAL: Failed to apply nftables ruleset.${N}"
  fi
  rm -f "$tmp"
}

# -------------------- Port management ---------------------
valid_port(){ [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }

process_ports(){
  # $1 add|remove  $2 TCP|UDP  $3 raw_input
  local action="$1" proto="$2" raw="$3" file count=0 ssh_port
  [[ "$proto" == "TCP" ]] && file="$TCP_FILE" || file="$UDP_FILE"
  ssh_port=$(detect_ssh_port)

  IFS=',' read -ra items <<< "$(echo "$raw" | tr ' ' ',' )"
  for item in "${items[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -z "$item" ]] && continue

    if [[ "$item" == *-* ]]; then
      local a=${item%-*} b=${item#*-}
      if valid_port "$a" && valid_port "$b" && (( a<=b )); then
        for ((p=a; p<=b; p++)); do
          if [[ "$action" == "add" ]]; then
            # never duplicate and never store SSH in file (we print SSH separately)
            if [[ "$proto" == "TCP" && "$p" -eq "$ssh_port" ]]; then
              continue
            fi
            grep -qx "$p" "$file" || { echo "$p" >> "$file"; ((count++)); }
          else
            if [[ "$proto" == "TCP" && "$p" -eq "$ssh_port" ]]; then
              continue
            fi
            if grep -qx "$p" "$file"; then
              sed -i "/^$p$/d" "$file"; ((count++))
            fi
          fi
        done
      else
        echo -e " -> ${R}Invalid range: $item${N}"
      fi
    else
      if valid_port "$item"; then
        if [[ "$action" == "add" ]]; then
          if [[ "$proto" == "TCP" && "$item" -eq "$ssh_port" ]]; then
            echo -e " -> ${Y}SSH port is auto-allowed; not stored in file.${N}"
            continue
          fi
          grep -qx "$item" "$file" || { echo "$item" >> "$file"; ((count++)); echo -e " -> ${G}Port $item added.${N}"; }
        else
          if [[ "$proto" == "TCP" && "$item" -eq "$ssh_port" ]]; then
            echo -e " -> ${R}Safety: cannot remove SSH from rules.${N}"
            continue
          fi
          if grep -qx "$item" "$file"; then
            sed -i "/^$item$/d" "$file"; ((count++)); echo -e " -> ${G}Port $item removed.${N}"
          else
            echo -e " -> ${Y}Port $item not found.${N}"
          fi
        fi
      else
        echo -e " -> ${R}Invalid port: $item${N}"
      fi
    fi
  done
  canon_file "$file"
  return $count
}

add_ports_menu(){
  local proto="$1" file
  [[ "$proto" == "TCP" ]] && file="$TCP_FILE" || file="$UDP_FILE"
  clear
  echo -e "${Y}--- Add Allowed $proto Ports ---${N}"
  echo "Current $proto: $(paste -sd, "$file" 2>/dev/null || echo "None")"
  read -r -p "Enter $proto port(s) to add (e.g., 80,443 or 1000-2000): " in < /dev/tty
  [[ -z "$in" ]] && return
  if process_ports add "$proto" "$in"; then :; fi
  apply_rules
  pause
}
remove_ports_menu(){
  local proto="$1" file
  [[ "$proto" == "TCP" ]] && file="$TCP_FILE" || file="$UDP_FILE"
  clear
  echo -e "${Y}--- Remove Allowed $proto Ports ---${N}"
  echo "Current $proto: $(paste -sd, "$file" 2>/dev/null || echo "None")"
  read -r -p "Enter $proto port(s) to remove: " in < /dev/tty
  [[ -z "$in" ]] && return
  if process_ports remove "$proto" "$in"; then :; fi
  apply_rules
  pause
}

# -------------------- Blocked IPs mgmt --------------------
valid_ipv4_cidr(){
  local s="$1" ip mask
  ip=${s%%/*}; mask=${s#*/}
  [[ "$s" == "$ip" ]] && mask=""
  IFS='.' read -r a b c d <<<"$ip" || return 1
  for o in "$a" "$b" "$c" "$d"; do [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)) || return 1; done
  if [[ -n "$mask" ]]; then [[ "$mask" =~ ^[0-9]+$ ]] && ((mask>=0 && mask<=32)) || return 1; fi
  return 0
}

add_ips(){
  local raw="$1" added=0
  IFS=',' read -ra items <<< "$(echo "$raw" | tr ' ' ',' )"
  for it in "${items[@]}"; do
    it="$(echo "$it" | xargs)"
    [[ -z "$it" ]] && continue
    if ! valid_ipv4_cidr "$it"; then
      echo -e " -> ${R}Invalid IPv4/CIDR: $it${N}"
      continue
    fi
    if ! grep -qxF "$it" "$BL_FILE"; then
      echo "$it" >> "$BL_FILE"; ((added++))
    else
      echo -e " -> ${Y}$it already present.${N}"
    fi
  done
  canon_file "$BL_FILE"
  return $added
}

remove_ips(){
  local raw="$1" removed=0 esc
  IFS=',' read -ra items <<< "$(echo "$raw" | tr ' ' ',' )"
  for it in "${items[@]}"; do
    it="$(echo "$it" | xargs)"
    [[ -z "$it" ]] && continue
    # escape for sed
    esc=$(printf '%s' "$it" | sed -e 's/[.[\*^$(){}?+|/\\]/\\&/g')
    if grep -qxF "$it" "$BL_FILE"; then
      sed -i "/^$esc\$/d" "$BL_FILE"; ((removed++))
    else
      echo -e " -> ${Y}$it not found.${N}"
    fi
  done
  canon_file "$BL_FILE"
  return $removed
}

manage_ips_menu(){
  while true; do
    clear
    canon_file "$BL_FILE"
    echo "--- Manage Blocked IPs ---"
    echo "Total: $(wc -l < "$BL_FILE" 2>/dev/null || echo 0)"
    echo
    echo "1) Add IP/CIDR"
    echo "2) Remove IP/CIDR"
    echo "3) Show first 100"
    echo "4) Back"
    read -r -p "Choose: " ch < /dev/tty
    case "$ch" in
      1) read -r -p "Enter IPs/CIDRs (comma/space/newline separated): " s < /dev/tty
         [[ -z "$s" ]] || add_ips "$s"
         apply_rules; pause ;;
      2) read -r -p "Enter IPs/CIDRs to remove: " s < /dev/tty
         [[ -z "$s" ]] || remove_ips "$s"
         apply_rules; pause ;;
      3) head -n 100 "$BL_FILE" 2>/dev/null | sed 's/^/  - /'; pause ;;
      4) break ;;
      *) echo "Invalid."; sleep 1 ;;
    esac
  done
}

# -------------------- View / Flush / Uninstall -------------
view_rules(){ clear; echo -e "${Y}--- Current Active NFTABLES Ruleset ---${N}"; nft list ruleset; pause; }

flush_reset(){
  clear
  read -r -p "ARE YOU SURE? This flushes all rules and resets config. (y/n): " a < /dev/tty
  [[ "$a" =~ ^[yY]$ ]] || { echo "Cancelled."; pause; return; }
  nft flush ruleset || true
  echo "flush ruleset" > /etc/nftables.conf
  systemctl restart nftables.service || true
  rm -rf "$CONFIG_DIR"
  ensure_dirs
  echo -e "${G}All rules flushed & configuration reset.${N}"
  # re-init minimum state
  ensure_ssh_in_tcp
  need_blocklist_ready
  pause
}

uninstall_all(){
  clear
  read -r -p "Uninstall firewall & script? (y/n): " a < /dev/tty
  [[ "$a" =~ ^[yY]$ ]] || { echo "Cancelled."; pause; return; }
  nft flush ruleset || true
  echo "flush ruleset" > /etc/nftables.conf
  systemctl restart nftables.service || true
  systemctl disable nftables.service >/dev/null 2>&1 || true
  rm -rf "$CONFIG_DIR"
  echo -e "${G}Firewall removed. Script will self-delete...${N}"
  # self-delete after returning to shell
  ( sleep 1; rm -f -- "$0" ) >/dev/null 2>&1 &
  pause
  exit 0
}

# -------------------- Menus -------------------------------
menu_tcp(){
  while true; do
    clear
    echo "--- Manage Allowed TCP Ports ---"
    echo "Current: $(paste -sd, "$TCP_FILE" 2>/dev/null || echo "None")  (SSH: $(detect_ssh_port) auto-allowed)"
    echo "1) Add"
    echo "2) Remove"
    echo "3) Back"
    read -r -p "Choose: " c < /dev/tty
    case "$c" in
      1) add_ports_menu "TCP" ;;
      2) remove_ports_menu "TCP" ;;
      3) break ;;
      *) echo "Invalid."; sleep 1 ;;
    esac
  done
}
menu_udp(){
  while true; do
    clear
    echo "--- Manage Allowed UDP Ports ---"
    echo "Current: $(paste -sd, "$UDP_FILE" 2>/dev/null || echo "None")"
    echo "1) Add"
    echo "2) Remove"
    echo "3) Back"
    read -r -p "Choose: " c < /dev/tty
    case "$c" in
      1) add_ports_menu "UDP" ;;
      2) remove_ports_menu "UDP" ;;
      3) break ;;
      *) echo "Invalid."; sleep 1 ;;
    esac
  done
}

main_menu(){
  while true; do
    clear
    echo "==============================="
    echo " NFTABLES FIREWALL MANAGER v8.4"
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
    read -r -p "Choose an option: " opt < /dev/tty
    case "$opt" in
      1) view_rules ;;
      2) apply_rules ;;
      3) menu_tcp ;;
      4) menu_udp ;;
      5) manage_ips_menu ;;
      6) update_blocklist; apply_rules; pause ;;
      7) flush_reset ;;
      8) uninstall_all ;;
      9) exit 0 ;;
      *) echo "Invalid."; sleep 1 ;;
    esac
  done
}

# -------------------- Entry -------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  echo -e "${R}Run as root (sudo).${N}" >&2; exit 1
fi
prepare_system
ensure_dirs
ensure_ssh_in_tcp
need_blocklist_ready
main_menu
