#!/bin/bash
set -euo pipefail

# ===============================================================
#  NFTABLES FIREWALL MANAGER  v8.3  (set-based blocklist)
# ===============================================================
# - Debian/Ubuntu, root required
# - Docker-safe (auto-accept docker0/br-* if present)
# - Blocklist via nft "set" (fast)
# - Allows BOTH TCP and UDP ports you configure (XHTTP/QUIC/WS/gRPC)
# - Uninstall fully flushes rules and removes files (option 8)
# ===============================================================

# ----- Paths / Config -----
CONFIG_DIR="/etc/firewall_manager_nft"
TCP_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
UDP_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BL_FILE="$CONFIG_DIR/blocked_ips.conf"
FIRST_RUN_MARK="$CONFIG_DIR/.prep_done"
BIN_PATH="/usr/local/bin/firewall-manager"

# Source you can change later
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# ----- Colors -----
GREEN='\033[0;32m'; YEL='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

press_enter(){ echo; read -r -p "Press Enter to return..." < /dev/tty; }

ensure_dirs(){
  mkdir -p "$CONFIG_DIR"
  : >"$TCP_FILE" 2>/dev/null || true
  : >"$UDP_FILE" 2>/dev/null || true
  : >"$BL_FILE"  2>/dev/null || true
}

prepare_system(){
  ensure_dirs
  if [[ -f "$FIRST_RUN_MARK" ]]; then
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nftables curl iproute2
  systemctl enable nftables >/dev/null 2>&1 || true
  systemctl start nftables  >/dev/null 2>&1 || true
  touch "$FIRST_RUN_MARK"
}

detect_ssh_port(){
  # Try to find the port sshd is actually listening on; fallback 22
  local p
  p="$(ss -ltnp 2>/dev/null | awk '/sshd/ && /LISTEN/ {sub(/.*:/,"",$4); print $4}' | sort -u | head -n1 || true)"
  if [[ -z "${p:-}" ]]; then
    p="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
  fi
  [[ "$p" =~ ^[0-9]+$ ]] && echo "$p" || echo 22
}

ensure_ssh_allowed(){
  local sshp; sshp="$(detect_ssh_port)"
  if ! grep -qx "$sshp" "$TCP_FILE" 2>/dev/null; then
    echo "$sshp" >> "$TCP_FILE"
  fi
}

docker_ifaces(){
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '/^(docker0|br-)/{print $1}'
}

# ---------- Blocklist helpers ----------
canonicalize_bl(){
  # Remove comments/blank, trim, unique
  local t; t="$(mktemp)"
  awk '{gsub(/\r/,"")}
       /^[[:space:]]*#/ {next}
       {gsub(/^[[:space:]]+|[[:space:]]+$/,""); if(length) print $0}' "$BL_FILE" 2>/dev/null \
       | sort -u > "$t"
  mv "$t" "$BL_FILE"
}

default_bl_if_empty(){
  if [[ ! -s "$BL_FILE" ]]; then
    cat >"$BL_FILE" <<'EOT'
# Private / reserved / bogon (short)
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
EOT
  fi
  canonicalize_bl
}

update_blocklist(){
  echo -e "${YEL}Downloading latest blocklist...${NC}"
  local t rc
  t="$(mktemp)"
  rc=0
  if curl -fsSL "$BLOCKLIST_URL" -o "$t"; then
    if [[ -s "$t" ]] && [[ $(wc -l <"$t") -gt 10 ]]; then
      awk '{gsub(/\r/,"")}
           /^[[:space:]]*#/ {next}
           {gsub(/^[[:space:]]+|[[:space:]]+$/,""); if(length) print $0}' "$t" | sort -u > "$BL_FILE"
      rc=1
      echo -e "${GREEN}Blocklist updated.${NC}"
    fi
  fi
  rm -f "$t"
  return $rc
}

# ---------- Ruleset builder ----------
apply_rules(){
  clear
  echo "[+] Building new nftables ruleset..."

  ensure_dirs
  ensure_ssh_allowed
  default_bl_if_empty

  # Read current config
  local sshp; sshp="$(detect_ssh_port)"
  local tports uports
  tports="$(sort -un "$TCP_FILE" 2>/dev/null | paste -sd, -)"
  uports="$(sort -un "$UDP_FILE" 2>/dev/null | paste -sd, -)"

  # Load blocklist into an array (already cleaned)
  mapfile -t BL_ARR < <(cat "$BL_FILE")

  # Gather docker ifaces
  mapfile -t D_IF < <(docker_ifaces || true)

  # Rebuild fresh table
  nft list table inet firewall-manager >/dev/null 2>&1 && nft delete table inet firewall-manager

  local tmp; tmp="$(mktemp)"
  {
    echo "table inet firewall-manager {"

    # set with interval for prefixes
    echo "  set blocked_ips {"
    echo "    type ipv4_addr"
    echo "    flags interval"
    echo -n "    elements = {"
    if ((${#BL_ARR[@]})); then
      local first=1
      for ip in "${BL_ARR[@]}"; do
        [[ -z "$ip" ]] && continue
        if [[ $first -eq 1 ]]; then
          printf " %s" "$ip"
          first=0
        else
          printf ", %s" "$ip"
        fi
      done
    fi
    echo " }"
    echo "  }"

    # INPUT
    cat <<'EOF'
  chain input {
    type filter hook input priority 0; policy drop;
    ct state { established, related } accept
    iif lo accept
    ct state invalid drop
    icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept
    ip saddr @blocked_ips drop
EOF
    printf '    tcp dport %s accept\n' "$sshp"
    if [[ -n "${tports:-}" ]]; then
      echo "    tcp dport { $tports } accept"
    fi
    if [[ -n "${uports:-}" ]]; then
      echo "    udp dport { $uports } accept"
    fi
    echo "  }"

    # FORWARD
    cat <<'EOF'
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state { established, related } accept
    ct state invalid drop
    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
    ip daddr @blocked_ips drop
EOF
    if ((${#D_IF[@]})); then
      for ifc in "${D_IF[@]}"; do
        printf '    iifname "%s" accept\n' "$ifc"
        printf '    oifname "%s" accept\n' "$ifc"
      done
    fi
    echo "  }"

    # OUTPUT
    cat <<'EOF'
  chain output {
    type filter hook output priority 0; policy accept;
    ip daddr @blocked_ips drop
  }
}
EOF
  } >"$tmp"

  if nft -f "$tmp"; then
    echo -e "${GREEN}Applied.${NC}"
    echo "Saving to /etc/nftables.conf ..."
    nft list ruleset > /etc/nftables.conf
    systemctl restart nftables >/dev/null 2>&1 || true
    echo -e "${GREEN}Persisted.${NC}"
  else
    echo -e "${RED}FATAL: Failed to apply nftables ruleset!${NC}"
  fi
  rm -f "$tmp"
  press_enter
}

prompt_apply(){ apply_rules; }

# ---------- Port/IP editors ----------
valid_port(){ [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

parse_ports(){
  # stdout: only the number of changes; messages to stderr
  local action="$1" file="$2" list="$3" changed=0
  IFS=',' read -ra items <<<"$(echo "$list" | tr ' ' ',' )"
  local sshp; sshp="$(detect_ssh_port)"
  for raw in "${items[@]}"; do
    local v="${raw//[[:space:]]/}"
    [[ -z "$v" ]] && continue
    if [[ "$v" == *-* ]]; then
      local a="${v%-*}" b="${v#*-}"
      if valid_port "$a" && valid_port "$b" && ((a<=b)); then
        for ((p=a; p<=b; p++)); do
          if [[ "$action" == add ]]; then
            grep -qx "$p" "$file" 2>/dev/null || { echo "$p" >>"$file"; ((changed++)); }
          else
            # protect ssh in TCP file
            if [[ "$file" == "$TCP_FILE" && "$p" -eq "$sshp" ]]; then continue; fi
            if grep -qx "$p" "$file" 2>/dev/null; then
              sed -i "/^${p}\$/d" "$file"; ((changed++))
            fi
          fi
        done
        printf " -> range %s processed\n" "$v" >&2
      else
        printf " -> invalid range: %s\n" "$v" >&2
      fi
    else
      if valid_port "$v"; then
        if [[ "$action" == add ]]; then
          grep -qx "$v" "$file" 2>/dev/null || { echo "$v" >>"$file"; ((changed++)); printf " -> port %s added\n" "$v" >&2; }
        else
          if [[ "$file" == "$TCP_FILE" && "$v" -eq "$sshp" ]]; then
            printf " -> skip SSH port %s (safety)\n" "$sshp" >&2
          elif grep -qx "$v" "$file" 2>/dev/null; then
            sed -i "/^${v}\$/d" "$file"; ((changed++)); printf " -> port %s removed\n" "$v" >&2
          else
            printf " -> port %s not present\n" "$v" >&2
          fi
        fi
      else
        printf " -> invalid port: %s\n" "$v" >&2
      fi
    fi
  done
  echo "$changed"
}

add_ports_ui(){
  local proto="$1" file cur inp changed
  file="$TCP_FILE"; [[ "$proto" == "UDP" ]] && file="$UDP_FILE"
  clear
  echo -e "${YEL}--- Add Allowed ${proto} Ports ---${NC}"
  cur="$(sort -n "$file" 2>/dev/null | paste -sd, -)"
  echo "Current $proto: ${cur:-None}"
  read -r -p "Enter ${proto} port(s) to add (e.g., 80,443 or 1000-2000): " inp < /dev/tty
  [[ -z "${inp:-}" ]] && return
  changed="$(parse_ports add "$file" "$inp")"
  if (( changed > 0 )); then
    echo -e "${YEL}Applying firewall...${NC}"
    apply_rules
  else
    echo "No changes."
    press_enter
  fi
}

remove_ports_ui(){
  local proto="$1" file cur inp changed
  file="$TCP_FILE"; [[ "$proto" == "UDP" ]] && file="$UDP_FILE"
  clear
  echo -e "${YEL}--- Remove Allowed ${proto} Ports ---${NC}"
  cur="$(sort -n "$file" 2>/dev/null | paste -sd, -)"
  echo "Current $proto: ${cur:-None}"
  read -r -p "Enter ${proto} port(s) to remove: " inp < /dev/tty
  [[ -z "${inp:-}" ]] && return
  changed="$(parse_ports remove "$file" "$inp")"
  if (( changed > 0 )); then
    echo -e "${YEL}Applying firewall...${NC}"
    apply_rules
  else
    echo "No changes."
    press_enter
  fi
}

# ---------- Blocked IPs UI ----------
valid_ipv4_cidr(){
  local s="$1" ip mask
  ip="${s%%/*}"; mask="${s#*/}"; [[ "$s" == "$ip" ]] && mask=""
  IFS='.' read -r a b c d <<<"$ip" || return 1
  for o in "$a" "$b" "$c" "$d"; do [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0&&o<=255)) || return 1; done
  if [[ -n "$mask" ]]; then [[ "$mask" =~ ^[0-9]+$ ]] && ((mask>=0&&mask<=32)) || return 1; fi
  return 0
}

edit_ips_ui(){
  while true; do
    clear
    canonicalize_bl
    echo "--- Manage Blocked IPs ---"
    echo "Total: $(wc -l < "$BL_FILE" 2>/dev/null || echo 0)"
    echo "Preview:"
    head -n 30 "$BL_FILE" 2>/dev/null | sed 's/^/  - /' || true
    echo
    echo "1) Add IP/CIDR"
    echo "2) Remove IP/CIDR"
    echo "3) Show full list"
    echo "4) Back"
    read -r -p "Choose: " c < /dev/tty
    case "$c" in
      1)
        read -r -p "Enter IPs/CIDRs (comma/space separated): " s < /dev/tty
        s="$(echo "$s" | tr ' ' ',' )"
        IFS=',' read -ra arr <<<"$s"
        local changed=0
        for x in "${arr[@]}"; do
          x="$(echo "$x" | xargs)"
          [[ -z "$x" ]] && continue
          if valid_ipv4_cidr "$x"; then
            grep -qxF "$x" "$BL_FILE" || { echo "$x" >>"$BL_FILE"; ((changed++)); }
          else
            echo " -> invalid: $x"
          fi
        done
        canonicalize_bl
        if ((changed>0)); then echo -e "${YEL}Applying...${NC}"; apply_rules; fi
        ;;
      2)
        read -r -p "Enter IPs/CIDRs to remove: " s < /dev/tty
        s="$(echo "$s" | tr ' ' ',' )"
        IFS=',' read -ra arr <<<"$s"
        local changed=0
        for x in "${arr[@]}"; do
          x="$(echo "$x" | xargs)"
          [[ -z "$x" ]] && continue
          if grep -qxF "$x" "$BL_FILE"; then
            sed -i "/^$(printf '%s' "$x" | sed 's/[.[\*^$()+?{}/\\|]/\\&/g')\$/d" "$BL_FILE"
            ((changed++))
          fi
        done
        canonicalize_bl
        if ((changed>0)); then echo -e "${YEL}Applying...${NC}"; apply_rules; fi
        ;;
      3) ${PAGER:-less} "$BL_FILE" </dev/tty || cat "$BL_FILE";;
      4) break ;;
      *) echo "Invalid"; sleep 1 ;;
    esac
  done
}

# ---------- Utilities ----------
view_rules(){
  clear
  echo -e "${YEL}--- Current Active NFTABLES Ruleset ---${NC}"
  nft list ruleset || true
  press_enter
}

flush_all(){
  clear
  read -r -p "This will FLUSH all rules and reset config. Continue? (y/n): " y < /dev/tty
  if [[ "$y" =~ ^[yY]$ ]]; then
    nft flush ruleset || true
    echo 'flush ruleset' | tee /etc/nftables.conf >/dev/null
    systemctl restart nftables >/dev/null 2>&1 || true
    rm -rf "$CONFIG_DIR"
    ensure_dirs
    echo -e "${GREEN}All rules flushed and config reset.${NC}"
  else
    echo "Cancelled."
  fi
  press_enter
}

uninstall_script(){
  clear
  echo -e "${RED}--- UNINSTALL FIREWALL & SCRIPT ---${NC}"
  read -r -p "Uninstall firewall & script? (y/n): " y < /dev/tty
  if [[ "$y" =~ ^[yY]$ ]]; then
    echo "[+] Flushing nftables & disabling persistence..."
    nft flush ruleset || true
    echo 'flush ruleset' | tee /etc/nftables.conf >/dev/null
    systemctl restart nftables >/dev/null 2>&1 || true

    echo "[+] Removing config & launcher..."
    rm -rf "$CONFIG_DIR"
    rm -f "$BIN_PATH"

    echo -e "${GREEN}Firewall removed. Delete this script file manually if needed.${NC}"
    press_enter
    exit 0
  else
    echo "Cancelled."
    press_enter
  fi
}

install_permanently(){
  clear
  read -r -p "Install launcher to ${BIN_PATH}? (y/n): " y < /dev/tty
  if [[ "$y" =~ ^[yY]$ ]]; then
    install -m 0755 "$0" "$BIN_PATH"
    echo -e "${GREEN}Installed. Run with: firewall-manager${NC}"
  else
    echo "Skipped."
  fi
  press_enter
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
    echo "9) Install Launcher (/usr/local/bin)"
    echo "0) Exit"
    echo "-------------------------------"
    read -r -p "Choose an option: " c < /dev/tty
    case "$c" in
      1) view_rules ;;
      2) apply_rules ;;
      3) while true; do
           clear; echo "--- Manage Allowed TCP Ports ---"
           echo "1) Add"; echo "2) Remove"; echo "3) Back"
           read -r -p "Choose: " s < /dev/tty
           case "$s" in
             1) add_ports_ui "TCP" ;;
             2) remove_ports_ui "TCP" ;;
             3) break ;;
             *) echo "Invalid"; sleep 1 ;;
           esac
         done ;;
      4) while true; do
           clear; echo "--- Manage Allowed UDP Ports ---"
           echo "1) Add"; echo "2) Remove"; echo "3) Back"
           read -r -p "Choose: " s < /dev/tty
           case "$s" in
             1) add_ports_ui "UDP" ;;
             2) remove_ports_ui "UDP" ;;
             3) break ;;
             *) echo "Invalid"; sleep 1 ;;
           esac
         done ;;
      5) edit_ips_ui ;;
      6) update_blocklist >/dev/null || echo "Blocklist unchanged."; press_enter; apply_rules ;;
      7) flush_all ;;
      8) uninstall_script ;;
      9) install_permanently ;;
      0) exit 0 ;;
      *) echo "Invalid"; sleep 1 ;;
    esac
  done
}

# ---------- Entry ----------
if [[ "$(id -u)" -ne 0 ]]; then
  echo -e "${RED}Please run as root (sudo).${NC}" >&2
  exit 1
fi
prepare_system
ensure_ssh_allowed
main_menu
