#!/bin/bash
set -euo pipefail

# =================================================================
#        Interactive NFTABLES Firewall Manager - v7.8
# =================================================================
# - First-run system prep only once (state file)
# - Detect SSH port automatically and protect it
# - Manage allowed TCP/UDP ports and IPv4 blocklist
# - Docker-friendly (keeps published ports working)
# - Blocks egress to blocked ranges BEFORE Docker bridge accepts
# - FIX: removed duplicate ip saddr block in FORWARD chain

# --- CONFIGURATION ---
CONFIG_DIR="/etc/firewall_manager_nft"
STATE_FILE="$CONFIG_DIR/.firstrun_done"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# --- COLORS ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

press_enter_to_continue() { echo ""; read -r -p "Press Enter to return..." < /dev/tty; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2
    exit 1
  fi
}

prepare_system() {
  mkdir -p "$CONFIG_DIR"
  if [ ! -f "$STATE_FILE" ]; then
    echo "[+] First run detected: updating system and installing dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null
    apt-get -y upgrade >/dev/null || true
    apt-get install -y nftables curl >/dev/null
    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl start nftables >/dev/null 2>&1 || true
    echo "done" > "$STATE_FILE"
    echo "Initial system preparation complete."
  else
    echo "[+] First-run system prep already done; skipping updates & installs."
  fi
}

detect_ssh_port() {
  # Prefer live socket; fall back to sshd_config; default 22
  local p
  p="$(ss -ltnp 2>/dev/null | awk '/sshd/ && /LISTEN/ {sub(/^.*:/,"",$4); print $4}' | head -n1 || true)"
  if [[ -z "$p" ]]; then
    p="$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 || true)"
  fi
  echo "${p:-22}"
}

create_default_blocked_ips_fallback() {
  cat > "$BLOCKED_IPS_FILE" <<'EOL'
# FALLBACK LIST (download failed)
10.0.0.0/8
100.64.0.0/10
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
198.18.0.0/15
EOL
}

update_blocklist() {
  local is_initial=${1:-false}
  echo -e "${YELLOW}Attempting to download latest blocklist from source...${NC}"
  local tmp; tmp="$(mktemp)"
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    if [ -s "$tmp" ] && [ "$(wc -l < "$tmp")" -gt 10 ]; then
      sed -i 's/\r$//' "$tmp"
      mv "$tmp" "$BLOCKED_IPS_FILE"
      echo -e "${GREEN}Blocklist successfully downloaded and updated.${NC}"
      if [[ "$is_initial" == false ]]; then prompt_to_apply; fi
    else
      echo -e "${RED}Downloaded file empty/suspicious. Keeping existing list.${NC}"
      rm -f "$tmp"; return 1
    fi
  else
    echo -e "${RED}Failed to download blocklist.${NC}"
    rm -f "$tmp"; return 1
  fi
  return 0
}

canonicalize_blocklist_to_array() {
  # -> BLOCKED_CLEAN[] unique, no comments/blank/CR
  local line
  local tmp_arr=()
  [ -f "$BLOCKED_IPS_FILE" ] || touch "$BLOCKED_IPS_FILE"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"                # strip trailing comment
    line="$(echo "$line" | tr -d '\r' | xargs || true)"
    [[ -z "$line" ]] && continue
    tmp_arr+=("$line")
  done < "$BLOCKED_IPS_FILE"
  mapfile -t BLOCKED_CLEAN < <(printf "%s\n" "${tmp_arr[@]}" | sort -u)
}

discover_docker_bridges() {
  # Outputs list of docker bridge names (docker0 and br-xxxxxxxxxxxx)
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
    | grep -E '^(docker0|br-[0-9a-f]{12})$' || true
}

apply_rules() {
  local no_pause=false
  [[ "${1:-}" == "--no-pause" ]] && no_pause=true
  [[ "$no_pause" == false ]] && clear

  echo "[+] Building new nftables ruleset..."

  # Safety: ensure config files exist
  mkdir -p "$CONFIG_DIR"
  touch "$ALLOWED_TCP_PORTS_FILE" "$ALLOWED_UDP_PORTS_FILE" "$BLOCKED_IPS_FILE"

  local ssh_port; ssh_port="$(detect_ssh_port)"

  # Read allowed ports (unique, numeric)
  local tcp_ports udp_ports
  tcp_ports="$(grep -E '^[0-9]+$' "$ALLOWED_TCP_PORTS_FILE" | sort -un | grep -v "^${ssh_port}$" | paste -sd, - || true)"
  udp_ports="$(grep -E '^[0-9]+$' "$ALLOWED_UDP_PORTS_FILE" | sort -un | paste -sd, - || true)"

  # Load/clean blocklist
  canonicalize_blocklist_to_array

  # Build ruleset
  {
    printf "flush ruleset\n"
    printf "table inet firewall-manager {\n"

    # INPUT
    printf "  chain input {\n"
    printf "    type filter hook input priority filter; policy drop;\n"
    printf "    ct state { established, related } accept\n"
    printf "    iif \"lo\" accept\n"
    printf "    ct state invalid drop\n"
    # Block suspicious sources inbound
    if ((${#BLOCKED_CLEAN[@]})); then
      for ip in "${BLOCKED_CLEAN[@]}"; do printf "    ip saddr %s drop\n" "$ip"; done
    fi
    # SSH and allowed ports
    printf "    tcp dport %s accept\n" "$ssh_port"
    if [[ -n "$tcp_ports" ]]; then printf "    tcp dport { %s } accept\n" "$tcp_ports"; fi
    if [[ -n "$udp_ports" ]]; then printf "    udp dport { %s } accept\n" "$udp_ports"; fi
    printf "  }\n\n"

    # FORWARD
    printf "  chain forward {\n"
    printf "    type filter hook forward priority filter; policy drop;\n"
    printf "    ct state { established, related } accept\n"
    printf "    ct state invalid drop\n"
    # Block egress to blocked destinations BEFORE Docker accepts
    if ((${#BLOCKED_CLEAN[@]})); then
      for ip in "${BLOCKED_CLEAN[@]}"; do printf "    ip daddr %s drop\n" "$ip"; done
    fi
    # Allow docker bridges (both directions)
    while read -r br; do
      [[ -z "$br" ]] && continue
      printf "    iifname \"%s\" accept\n" "$br"
      printf "    oifname \"%s\" accept\n" "$br"
    done < <(discover_docker_bridges)
    # (Keep ONE source-block list after docker accepts)
    if ((${#BLOCKED_CLEAN[@]})); then
      for ip in "${BLOCKED_CLEAN[@]}"; do printf "    ip saddr %s drop\n" "$ip"; done
    fi
    printf "  }\n\n"

    # OUTPUT
    printf "  chain output {\n"
    printf "    type filter hook output priority filter; policy accept;\n"
    if ((${#BLOCKED_CLEAN[@]})); then
      for ip in "${BLOCKED_CLEAN[@]}"; do printf "    ip daddr %s drop\n" "$ip"; done
    fi
    printf "  }\n"

    printf "}\n"
  } > /tmp/.nft.rules.$$


  if nft -f /tmp/.nft.rules.$$; then
    echo -e "\n${GREEN}Firewall configuration applied successfully!${NC}"
    echo -e "${YELLOW}Saving rules to make them persistent...${NC}"
    nft list ruleset > /etc/nftables.conf
    systemctl restart nftables >/dev/null 2>&1 || true
    echo -e "${GREEN}Rules have been made persistent.${NC}"
  else
    echo -e "\n${RED}FATAL: Failed to apply nftables ruleset!${NC}"
    echo "Check for syntax errors or invalid entries in your config files."
  fi
  rm -f /tmp/.nft.rules.$$

  [[ "$no_pause" == false ]] && press_enter_to_continue
}

prompt_to_apply() {
  echo ""
  read -r -p "Apply these changes now to make them live? (y/n): " confirm < /dev/tty
  if [[ "$confirm" =~ ^[Yy]$ ]]; then apply_rules --no-pause
  else echo -e "${YELLOW}Changes saved to config but NOT applied.${NC}"; fi
}

parse_and_process_ports() {
  local action="$1" proto_file="$2" input_ports="$3"
  local count=0
  local ssh_port; ssh_port="$(detect_ssh_port)"

  IFS=',' read -ra port_items <<< "$input_ports"
  for item in "${port_items[@]}"; do
    item="$(echo "$item" | xargs)"
    if [[ "$item" == *-* ]]; then
      local a b; a="${item%-*}"; b="${item#*-}"
      if [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$a" -le "$b" ]]; then
        for ((p=a; p<=b; p++)); do
          if [[ "$action" == "remove" && "$proto_file" == "$ALLOWED_TCP_PORTS_FILE" && "$p" == "$ssh_port" ]]; then continue; fi
          if [[ "$action" == "add" && ! $(grep -qx "$p" "$proto_file" 2>/dev/null; echo $?) -eq 0 ]]; then
            echo "$p" >> "$proto_file"; ((count++))
          elif [[ "$action" == "remove" && $(grep -qx "$p" "$proto_file"; echo $?) -eq 0 ]]; then
            sed -i "/^${p}\$/d" "$proto_file"; ((count++))
          fi
        done
        echo -e " -> ${GREEN}Port range $item processed.${NC}"
      else
        echo -e " -> ${RED}Invalid range: $item${NC}"
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "remove" && "$proto_file" == "$ALLOWED_TCP_PORTS_FILE" && "$item" == "$ssh_port" ]]; then
        echo -e " -> ${RED}Safety: Cannot remove SSH port (${ssh_port}).${NC}"
        continue
      fi
      if [[ "$action" == "add" && ! $(grep -qx "$item" "$proto_file" 2>/dev/null; echo $?) -eq 0 ]]; then
        echo "$item" >> "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item added.${NC}"
      elif [[ "$action" == "remove" && $(grep -qx "$item" "$proto_file"; echo $?) -eq 0 ]]; then
        sed -i "/^${item}\$/d" "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item removed.${NC}"
      else
        echo -e " -> ${YELLOW}No change for $item.${NC}"
      fi
    elif [[ -n "$item" ]]; then
      echo -e " -> ${RED}Invalid input: $item${NC}"
    fi
  done

  if ((count>0)); then echo -e "\n${GREEN}Configuration file updated.${NC}"; prompt_to_apply
  else echo -e "\nNo changes were made."; fi
}

manage_ports_interactive() {
  local action="$1" proto="$2" file
  file="$ALLOWED_TCP_PORTS_FILE"; [[ "$proto" == "UDP" ]] && file="$ALLOWED_UDP_PORTS_FILE"
  while true; do
    clear
    echo -e "${YELLOW}--- ${action^} Allowed ${proto} Ports ---${NC}"
    echo -n "Current ${proto} ports: "
    (grep -E '^[0-9]+$' "$file" 2>/dev/null | sort -un | paste -sd, -) || echo "None"
    echo ""
    read -r -p "Enter ${proto} port(s) to ${action} (e.g., 80,443 or 1000-2000) or leave empty to go back: " input_ports < /dev/tty
    [[ -z "$input_ports" ]] && break
    parse_and_process_ports "$action" "$file" "$input_ports"
  done
}

# --- Blocklist manage ---
add_block_item() {
  local label="$1"
  while true; do
    clear
    echo -e "${YELLOW}--- Add ${label} ---${NC}"
    echo "Current list:"
    grep -v '^\s*#' "$BLOCKED_IPS_FILE" | sed '/^\s*$/d' | nl -ba || true
    echo ""
    read -r -p "Enter ${label} (IPv4 or CIDR) or empty to go back: " item < /dev/tty
    [[ -z "$item" ]] && return
    item="$(echo "$item" | xargs)"
    if [[ "$item" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
      echo "$item" >> "$BLOCKED_IPS_FILE"
      sort -u "$BLOCKED_IPS_FILE" -o "$BLOCKED_IPS_FILE"
      echo -e "${GREEN}${label} '$item' added.${NC}"
      prompt_to_apply
    else
      echo -e "${RED}Invalid IPv4/CIDR.${NC}"; press_enter_to_continue
    fi
  done
}

remove_block_item() {
  local label="$1"
  while true; do
    clear
    echo -e "${YELLOW}--- Remove ${label} ---${NC}"
    echo "Current list:"
    grep -v '^\s*#' "$BLOCKED_IPS_FILE" | sed '/^\s*$/d' | nl -ba || true
    echo ""
    read -r -p "Enter exact ${label} (IPv4 or CIDR) to remove or empty to go back: " item < /dev/tty
    [[ -z "$item" ]] && return
    if grep -qx "$item" "$BLOCKED_IPS_FILE"; then
      sed -i "/^${item//\//\\/}\$/d" "$BLOCKED_IPS_FILE"
      echo -e "${GREEN}${label} '$item' removed.${NC}"
      prompt_to_apply
    else
      echo -e "${RED}Not found: ${item}${NC}"; press_enter_to_continue
    fi
  done
}

manage_ips_menu() {
  while true; do
    clear
    echo "--- Manage Blocked IPs ---"
    echo "1) Add IP/CIDR"
    echo "2) Remove IP/CIDR"
    echo "3) Back"
    read -r -p "Choose an option: " c < /dev/tty
    case "$c" in
      1) add_block_item "IP/CIDR" ;;
      2) remove_block_item "IP/CIDR" ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
    esac
  done
}

view_rules() { clear; echo -e "${YELLOW}--- Current Active NFTABLES Ruleset ---${NC}"; nft list ruleset; press_enter_to_continue; }

flush_rules() {
  clear
  read -r -p "ARE YOU SURE? This will flush all rules and reset the configuration. (y/n): " confirm < /dev/tty
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo "[+] Flushing ruleset..."
    nft flush ruleset
    echo "flush ruleset" > /etc/nftables.conf
    systemctl restart nftables >/dev/null 2>&1 || true
    echo -e "${GREEN}All rules flushed. The firewall is now open.${NC}"
    rm -rf "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
    touch "$ALLOWED_TCP_PORTS_FILE" "$ALLOWED_UDP_PORTS_FILE"
    if ! update_blocklist true; then
      echo -e "${YELLOW}Using fallback local blocklist...${NC}"
      create_default_blocked_ips_fallback
    fi
  else
    echo "Operation cancelled."
  fi
  press_enter_to_continue
}

uninstall_script() {
  clear
  echo -e "${RED}--- UNINSTALL FIREWALL & SCRIPT ---${NC}"
  read -r -p "ARE YOU SURE you want to permanently delete the firewall and this script? (y/n): " confirm < /dev/tty
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    nft flush ruleset
    echo "flush ruleset" > /etc/nftables.conf
    systemctl restart nftables >/dev/null 2>&1 || true
    rm -rf "$CONFIG_DIR"
    echo -e "${GREEN}Firewall has been removed. The script will now self-destruct.${NC}"
    (sleep 1 && rm -f -- "$0") &
    exit 0
  else
    echo "Operation cancelled."
  fi
  press_enter_to_continue
}

initial_setup() {
  if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}First time setup: Creating configuration...${NC}"
    mkdir -p "$CONFIG_DIR"
    touch "$ALLOWED_TCP_PORTS_FILE" "$ALLOWED_UDP_PORTS_FILE"
    if ! update_blocklist true; then
      echo -e "${YELLOW}Using fallback local blocklist...${NC}"
      create_default_blocked_ips_fallback
    fi
    echo -e "\n${GREEN}Initial configuration complete.${NC}"
    echo "Use 'Apply Firewall Rules' to activate your setup."
    press_enter_to_continue
  fi
}

main_menu() {
  while true; do
    clear
    echo "NFTABLES FIREWALL MANAGER v7.8"
    echo "================================"
    echo "1) View Current Firewall Rules"
    echo "2) Apply Firewall Rules from Config"
    echo "3) Manage Allowed TCP Ports"
    echo "4) Manage Allowed UDP Ports"
    echo "5) Manage Blocked IPs"
    echo "6) Update IP Blocklist from Source"
    echo "7) Flush All Rules & Reset Config"
    echo "8) Uninstall Firewall & Script"
    echo "9) Exit"
    echo "--------------------------------"
    read -r -p "Choose an option: " choice < /dev/tty
    case "$choice" in
      1) view_rules ;;
      2) apply_rules ;;
      3) manage_ports_interactive "add/remove" "TCP" ;;   # shows a loop add/remove by prompt
      4) manage_ports_interactive "add/remove" "UDP" ;;
      5) manage_ips_menu ;;
      6) update_blocklist; press_enter_to_continue ;;
      7) flush_rules ;;
      8) uninstall_script ;;
      9) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
    esac
  done
}

# --- SCRIPT START ---
require_root
prepare_system
initial_setup
main_menu
