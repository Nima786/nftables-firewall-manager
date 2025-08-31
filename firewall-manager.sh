#!/usr/bin/env bash
set -euo pipefail

# =================================================================
#  NFTABLES Firewall Manager  v8.3.1  (compact set + port submenus)
# =================================================================

# --- CONFIG ---
CONFIG_DIR="/etc/firewall_manager_nft"
TCP_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
UDP_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BL_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# --- COLORS ---
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

press_enter(){ echo; read -r -p "Press Enter to return..." < /dev/tty; }

ensure_dirs(){
  mkdir -p "$CONFIG_DIR"
  [[ -f "$TCP_FILE" ]] || : >"$TCP_FILE"
  [[ -f "$UDP_FILE" ]] || : >"$UDP_FILE"
  [[ -f "$BL_FILE"  ]] || : >"$BL_FILE"
}

install_deps_once(){
  ensure_dirs
  if ! command -v nft >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y nftables curl
    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl start  nftables >/dev/null 2>&1 || true
  fi
}

detect_ssh_port(){
  local p=""
  p=$(ss -ltn 2>/dev/null | awk '/LISTEN/ && $4 ~ /:[0-9]+$/ {sub(/.*:/,"",$4); print $4}' \
      | while read -r x; do ss -ltnp "sport = :$x" 2>/dev/null | grep -q sshd && { echo "$x"; break; }; done || true)
  [[ -z "${p:-}" ]] && p=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 || true)
  [[ "$p" =~ ^[0-9]+$ ]] && ((p>=1 && p<=65535)) || p=22
  echo "$p"
}

ensure_ssh_in_tcpfile(){
  local s; s=$(detect_ssh_port)
  grep -qx "$s" "$TCP_FILE" || echo "$s" >> "$TCP_FILE"
}

# ---------- Blocklist (baseline + compact, overlap-safe) ----------
baseline_blocklist(){
  cat <<'EOT'
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
100.64.0.0/10
198.18.0.0/15
224.0.0.0/4
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
25.0.0.0/8
45.14.174.0/24
195.137.167.0/24
206.191.152.0/24
216.218.185.0/24
240.0.0.0/24
EOT
}

canonicalize_bl(){
  local t; t=$(mktemp)
  awk '
    { gsub(/\r/,"") }
    /^[[:space:]]*#/ { next }
    { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)) print $0 }
  ' "$BL_FILE" 2>/dev/null | sort -u > "$t"
  mv "$t" "$BL_FILE"
}

filter_for_interval(){
  canonicalize_bl
  local t; t=$(mktemp)

  local bfile; bfile=$(mktemp)
  baseline_blocklist | sort -u > "$bfile"

  local h224=0 h10=0 h172=0 h192168=0 h10064=0 h169254=0 h19818=0
  grep -qx "224.0.0.0/4"     "$bfile" && h224=1
  grep -qx "10.0.0.0/8"      "$bfile" && h10=1
  grep -qx "172.16.0.0/12"   "$bfile" && h172=1
  grep -qx "192.168.0.0/16"  "$bfile" && h192168=1
  grep -qx "100.64.0.0/10"   "$bfile" && h10064=1
  grep -qx "169.254.0.0/16"  "$bfile" && h169254=1
  grep -qx "198.18.0.0/15"   "$bfile" && h19818=1

  awk '
    BEGIN{
      print "10.0.0.0/8"
      print "172.16.0.0/12"
      print "192.168.0.0/16"
      print "169.254.0.0/16"
      print "100.64.0.0/10"
      print "198.18.0.0/15"
      print "224.0.0.0/4"
      print "192.0.2.0/24"
      print "198.51.100.0/24"
      print "203.0.113.0/24"
      print "25.0.0.0/8"
      print "45.14.174.0/24"
      print "195.137.167.0/24"
      print "206.191.152.0/24"
      print "216.218.185.0/24"
      print "240.0.0.0/24"
    }' /dev/null > "$t"

  awk -v h224="$h224" -v h10="$h10" -v h172="$h172" -v h192168="$h192168" \
      -v h10064="$h10064" -v h169254="$h169254" -v h19818="$h19818" '
    function covered(l){
      if (h224    && l ~ /^(22[4-9]|23[0-9])\./)                         return 1;
      if (h10     && l ~ /^10\./)                                       return 1;
      if (h172    && l ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./)              return 1;
      if (h192168 && l ~ /^192\.168\./)                                 return 1;
      if (h10064  && l ~ /^100\.(6[4-9]|[78][0-9]|9[01])\./)            return 1;
      if (h169254 && l ~ /^169\.254\./)                                 return 1;
      if (h19818  && l ~ /^198\.(18|19)\./)                             return 1;
      return 0
    }
    /^[[:space:]]*#/ {next}
    NF { if (!covered($0)) print $0 }
  ' "$BL_FILE" >> "$t"

  sort -u "$t"
  rm -f "$t" "$bfile"
}

update_blocklist(){
  echo -e "${Y}Downloading latest blocklist...${N}"
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    awk '
      { gsub(/\r/,"") }
      /^[[:space:]]*#/ { next }
      { gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)) print $0 }
    ' "$tmp" | sort -u > "$BL_FILE"
    rm -f "$tmp"
    echo -e "${G}Blocklist updated.${N}"
  else
    echo -e "${R}Could not download blocklist. Keeping existing entries.${N}"
    rm -f "$tmp" || true
  fi
}

docker_ifaces(){
  ip -o link show 2>/dev/null | awk -F': ' '/^(docker0|br-)/{print $2}'
}

apply_rules(){
  clear
  echo "[+] Building new nftables ruleset..."

  ensure_dirs
  ensure_ssh_in_tcpfile

  local sshp; sshp=$(detect_ssh_port)
  local tcp_list udp_list
  tcp_list=$({ grep -E '^[0-9]+$' "$TCP_FILE" 2>/dev/null | sort -un | grep -v -x "$sshp" || true; } | paste -sd, -)
  udp_list=$({ grep -E '^[0-9]+$' "$UDP_FILE" 2>/dev/null | sort -un || true; } | paste -sd, -)

  mapfile -t BL_CLEAN < <(filter_for_interval)

  nft list table inet firewall-manager >/dev/null 2>&1 && nft delete table inet firewall-manager

  local tmp; tmp=$(mktemp)
  {
    echo "table inet firewall-manager {"
    echo "  set blocked_ips {"
    echo "    type ipv4_addr"
    echo "    flags interval"
    echo -n "    elements = { "
    local first=1
    for e in "${BL_CLEAN[@]}"; do
      [[ -z "$e" ]] && continue
      if ((first)); then printf "%s" "$e"; first=0; else printf ", %s" "$e"; fi
    done
    echo " }"
    echo "  }"

    echo "  chain input {"
    echo "    type filter hook input priority filter; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    iif \"lo\" accept"
    echo "    ct state invalid drop"
    echo "    icmp type { echo-reply, destination-unreachable, echo-request, time-exceeded, parameter-problem } accept"
    echo "    ip saddr @blocked_ips drop"
    echo "    tcp dport $sshp accept"
    [[ -n "$tcp_list" ]] && echo "    tcp dport { $tcp_list } accept"
    [[ -n "$udp_list" ]] && echo "    udp dport { $udp_list } accept"
    echo "  }"

    echo "  chain forward {"
    echo "    type filter hook forward priority filter; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    ct state invalid drop"
    echo "    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept"
    echo "    ip daddr @blocked_ips drop"
    for d in $(docker_ifaces); do
      echo "    iifname \"$d\" accept"
      echo "    oifname \"$d\" accept"
    done
    echo "  }"

    echo "  chain output {"
    echo "    type filter hook output priority filter; policy accept;"
    echo "    ip daddr @blocked_ips drop"
    echo "  }"
    echo "}"
  } > "$tmp"

  if nft -f "$tmp"; then
    echo -e "Applied."
    echo -e "Saving to /etc/nftables.conf ..."
    nft list ruleset > /etc/nftables.conf
    systemctl restart nftables >/dev/null 2>&1 || true
    echo -e "${G}Persisted.${N}"
  else
    echo -e "${R}FATAL: Failed to apply nftables ruleset!${N}"
  fi
  rm -f "$tmp"
}

validate_port(){ [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }

edit_ports(){
  local mode="$1" file="$2"
  local label; label=$(basename "$file")   # (fix SC2034: no unused var)

  while true; do
    clear
    echo -e "${Y}--- Manage ${mode} Ports (${label}) ---${N}"
    echo -n "Current: "; (grep -E '^[0-9]+$' "$file" 2>/dev/null | sort -un | paste -sd, -) || echo
    echo "1) Add port(s)"
    echo "2) Remove port(s)"
    echo "3) Back"
    read -r -p "Choose: " ch < /dev/tty
    case "$ch" in
      1)
        read -r -p "Enter ${mode} port(s) (e.g., 80,443 or 2000-2005): " in < /dev/tty
        [[ -z "$in" ]] && continue
        local changed=0
        IFS=',' read -ra items <<< "$in"
        for x in "${items[@]}"; do
          x="$(echo "$x" | xargs)"
          if [[ "$x" == *-* ]]; then
            local a=${x%-*} b=${x#*-}
            if validate_port "$a" && validate_port "$b" && ((a<=b)); then
              for ((p=a; p<=b; p++)); do
                grep -qx "$p" "$file" || { echo "$p" >> "$file"; changed=1; }
              done
              echo " -> range $x added."
            else echo " -> invalid range: $x"; fi
          elif validate_port "$x"; then
            grep -qx "$x" "$file" || { echo "$x" >> "$file"; changed=1; echo " -> port $x added."; }
          else
            echo " -> invalid: $x"
          fi
        done
        ((changed)) && { echo -e "${Y}Applying firewall...${N}"; update_blocklist; apply_rules; } || echo "No changes."
        press_enter
        ;;
      2)
        read -r -p "Enter ${mode} port(s) to remove: " in < /dev/tty
        [[ -z "$in" ]] && continue
        local changed=0
        IFS=',' read -ra items <<< "$in"
        for x in "${items[@]}"; do
          x="$(echo "$x" | xargs)"
          if [[ "$x" == *-* ]]; then
            local a=${x%-*} b=${x#*-}
            if validate_port "$a" && validate_port "$b" && ((a<=b)); then
              for ((p=a; p<=b; p++)); do
                if grep -qx "$p" "$file"; then
                  sed -i "/^${p}\$/d" "$file"; changed=1
                fi
              done
              echo " -> range $x processed."
            else echo " -> invalid range: $x"; fi
          elif validate_port "$x"; then
            if grep -qx "$x" "$file"; then
              sed -i "/^${x}\$/d" "$file"; changed=1; echo " -> port $x removed."
            else
              echo " -> not found: $x"
            fi
          else
            echo " -> invalid: $x"
          fi
        done
        ((changed)) && { echo -e "${Y}Applying firewall...${N}"; update_blocklist; apply_rules; } || echo "No changes."
        press_enter
        ;;
      3) break ;;
      *) echo "Invalid."; sleep 1 ;;
    esac
  done
}

valid_ipv4_cidr(){
  local s="$1" ip=${1%%/*} mask=${1#*/}
  [[ "$s" == "$ip" ]] && mask=""
  IFS='.' read -r a b c d <<<"$ip" || return 1
  for o in "$a" "$b" "$c" "$d"; do [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)) || return 1; done
  if [[ -n "$mask" ]]; then [[ "$mask" =~ ^[0-9]+$ ]] && ((mask>=0 && mask<=32)) || return 1; fi
  return 0
}

manage_ips(){
  while true; do
    clear
    echo "--- Manage Blocked IPs ---"
    echo "First 50 entries:"
    head -n 50 "$BL_FILE" 2>/dev/null | sed 's/^/  - /' || true
    echo
    echo "1) Add IP/CIDR"
    echo "2) Remove IP/CIDR"
    echo "3) Back"
    read -r -p "Choose: " ch < /dev/tty
    case "$ch" in
      1)
        read -r -p "Enter IPs/CIDRs (comma/space ok): " s < /dev/tty
        s=$(echo "$s" | tr ' ' ',' )
        local changed=0
        IFS=',' read -ra arr <<< "$s"
        for it in "${arr[@]}"; do
          it=$(echo "$it" | xargs); [[ -z "$it" ]] && continue
          if valid_ipv4_cidr "$it"; then
            grep -qxF "$it" "$BL_FILE" || { echo "$it" >> "$BL_FILE"; changed=1; echo " -> added $it"; }
          else
            echo " -> invalid $it"
          fi
        done
        ((changed)) && { echo -e "${Y}Applying firewall...${N}"; apply_rules; } || echo "No changes."
        press_enter
        ;;
      2)
        read -r -p "Enter IPs/CIDRs to remove: " s < /dev/tty
        s=$(echo "$s" | tr ' ' ',' )
        local changed=0
        IFS=',' read -ra arr <<< "$s"
        for it in "${arr[@]}"; do
          it=$(echo "$it" | xargs); [[ -z "$it" ]] && continue
          if grep -qxF "$it" "$BL_FILE"; then
            # Use fixed-string exact-line removal (fixes SC2016)
            local tmp; tmp=$(mktemp)
            grep -Fvx "$it" "$BL_FILE" > "$tmp" || true
            mv "$tmp" "$BL_FILE"
            changed=1; echo " -> removed $it"
          else
            echo " -> not found $it"
          fi
        done
        ((changed)) && { echo -e "${Y}Applying firewall...${N}"; apply_rules; } || echo "No changes."
        press_enter
        ;;
      3) break ;;
      *) echo "Invalid."; sleep 1 ;;
    esac
  done
}

view_rules(){ clear; echo -e "${Y}--- Current Active NFTABLES Ruleset ---${N}"; nft list ruleset; press_enter; }

flush_all(){
  clear
  read -r -p "ARE YOU SURE? This will open the firewall and reset config. (y/n): " a < /dev/tty
  [[ "$a" =~ ^[yY]$ ]] || { echo "Cancelled."; press_enter; return; }
  nft flush ruleset || true
  echo "flush ruleset" > /etc/nftables.conf
  systemctl restart nftables >/dev/null 2>&1 || true
  rm -rf "$CONFIG_DIR"
  ensure_dirs
  echo -e "${G}Flushed and reset.${N}"
  press_enter
}

uninstall_self(){
  clear
  read -r -p "Uninstall firewall & script? (y/n): " a < /dev/tty
  [[ "$a" =~ ^[yY]$ ]] || { echo "Cancelled."; press_enter; return; }
  nft flush ruleset || true
  echo "flush ruleset" > /etc/nftables.conf
  systemctl restart nftables >/dev/null 2>&1 || true
  rm -rf "$CONFIG_DIR"
  echo -e "${G}Firewall removed. Delete this file manually if needed.${N}"
  press_enter
}

main_menu(){
  while true; do
    clear
    echo "==============================="
    echo " NFTABLES FIREWALL MANAGER v8.3.1"
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
    read -r -p "Choose an option: " c < /dev/tty
    case "$c" in
      1) view_rules ;;
      2) update_blocklist; apply_rules; press_enter ;;
      3) edit_ports "TCP" "$TCP_FILE" ;;
      4) edit_ports "UDP" "$UDP_FILE" ;;
      5) manage_ips ;;
      6) update_blocklist; echo "Done."; press_enter ;;
      7) flush_all ;;
      8) uninstall_self ;;
      9) exit 0 ;;
      *) echo "Invalid."; sleep 1 ;;
    esac
  done
}

[[ "$(id -u)" -eq 0 ]] || { echo -e "${R}Run as root (sudo).${N}"; exit 1; }
install_deps_once
ensure_dirs
ensure_ssh_in_tcpfile
main_menu
