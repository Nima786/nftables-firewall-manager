#!/bin/bash
set -euo pipefail

# =================================================================
#  Interactive NFTABLES Firewall Manager - v6.4
# =================================================================
# - First run: apt update && apt upgrade (tracked by state file)
# - Subsequent runs: quick apt metadata refresh only
# - Detects & auto-allows current SSH port
# - Installs deps (nftables, curl)
# - Overlap-safe blocklist (per-rule drops; no interval sets)
# - Deterministic load: delete table IF it exists (no error spam)
# - TCP/UDP submenus: stay open; changes auto-apply (no prompt)
# - Forward chain: only ip saddr drops (avoid duplicate-looking lines)

# --- CONFIG ---
CONFIG_DIR="/etc/firewall_manager_nft"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"
STATE_FILE="$CONFIG_DIR/.first_run_done"

# --- COLORS ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

press_enter_to_continue(){ echo ""; read -r -p "Press Enter to return..." < /dev/tty; }
ensure_config_dir(){
  mkdir -p "$CONFIG_DIR"
  [ -f "$ALLOWED_TCP_PORTS_FILE" ] || touch "$ALLOWED_TCP_PORTS_FILE"
  [ -f "$ALLOWED_UDP_PORTS_FILE" ] || touch "$ALLOWED_UDP_PORTS_FILE"
  [ -f "$BLOCKED_IPS_FILE" ]      || touch "$BLOCKED_IPS_FILE"
}

# ---------------- System prep & deps ----------------
prepare_system(){
  echo "[+] Checking apt metadata & dependencies..."
  export DEBIAN_FRONTEND=noninteractive

  if [ ! -f "$STATE_FILE" ]; then
    echo "[+] First run detected: apt update && apt upgrade..."
    apt-get update -y
    apt-get -y upgrade || true
  else
    apt-get update -y >/dev/null 2>&1 || true
  fi

  local pkgs=()
  command -v nft  >/dev/null 2>&1 || pkgs+=("nftables")
  command -v curl >/dev/null 2>&1 || pkgs+=("curl")
  if ((${#pkgs[@]})); then
    echo "[+] Installing: ${pkgs[*]}"
    apt-get install -y "${pkgs[@]}"
  fi

  if ! command -v nft >/dev/null 2>&1; then
    echo -e "${RED}FATAL: nftables not available after install.${NC}"; exit 1
  fi
  systemctl enable nftables.service >/dev/null 2>&1 || true
  systemctl start  nftables.service  >/dev/null 2>&1 || true
  echo -e "${GREEN}System ready. Dependencies OK.${NC}"
}

# ---------------- SSH port detection ----------------
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
ensure_ssh_in_config(){ local ssh_port; ssh_port=$(detect_ssh_port); grep -qx "$ssh_port" "$ALLOWED_TCP_PORTS_FILE" || echo "$ssh_port" >> "$ALLOWED_TCP_PORTS_FILE"; }

# ---------------- Blocklist handling ----------------
update_blocklist(){
  local is_initial=${1:-false}
  echo -e "${YELLOW}Downloading latest blocklist...${NC}"
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    if [ -s "$tmp" ] && [ "$(wc -l < "$tmp")" -gt 10 ]; then
      sed -i 's/\r$//' "$tmp"; mv "$tmp" "$BLOCKED_IPS_FILE"
      echo -e "${GREEN}Blocklist updated.${NC}"
      [[ "$is_initial" == false ]] && prompt_to_apply
      return 0
    fi
  fi
  echo -e "${RED}Blocklist download failed or too small. Keeping existing.${NC}"
  rm -f "$tmp" || true
  return 1
}
create_default_blocked_ips_fallback(){
  cat > "$BLOCKED_IPS_FILE" << 'EOL'
# FALLBACK LIST
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOL
}
get_clean_blocklist(){ awk '
  /^[[:space:]]*#/ { next }
  /^[[:space:]]*$/ { next }
  { gsub(/\r/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,""); if (length($0)>0) print $0 }
' "$BLOCKED_IPS_FILE" | sort -u; }

# ---------------- First-time setup ----------------
initial_setup(){
  if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}First-time setup: creating configuration...${NC}"
    ensure_config_dir
    local ssh_port; ssh_port=$(detect_ssh_port)
    echo -e "${GREEN}Detected SSH on ${ssh_port}/tcp; it will be allowed automatically.${NC}"
    ensure_ssh_in_config
    if ! update_blocklist true; then
      echo -e "${YELLOW}Using a fallback local blocklist...${NC}"
      create_default_blocked_ips_fallback
    fi
    add_ports_interactive "TCP" --no-prompt
    echo -e "\n${GREEN}Initial configuration complete.${NC}"
    echo "Select 'Apply Firewall Rules' to activate."
    touch "$STATE_FILE"
    press_enter_to_continue
  else
    ensure_ssh_in_config
  fi
}

# ---------------- Apply nft rules ----------------
apply_rules(){
  local no_pause=false; [[ "${1:-}" == "--no-pause" ]] && no_pause=true
  [[ "$no_pause" == false ]] && clear
  echo "[+] Building new nftables ruleset..."

  ensure_config_dir
  local ssh_port; ssh_port=$(detect_ssh_port)
  ensure_ssh_in_config

  local tcp_ports udp_ports
  tcp_ports=$({ sort -un "$ALLOWED_TCP_PORTS_FILE" 2>/dev/null | grep -v -x "${ssh_port}" || true; } | tr '\n' ',' | sed 's/,$//')
  udp_ports=$({ sort -un "$ALLOWED_UDP_PORTS_FILE"  2>/dev/null || true; } | tr '\n' ',' | sed 's/,$//')

  mapfile -t BLOCKED_CLEAN < <(get_clean_blocklist)

  # Delete existing table if present (don’t error if missing)
  if nft list table inet firewall-manager >/dev/null 2>&1; then
    nft delete table inet firewall-manager
  fi

  # Build a fresh table into a temp file and load it
  local tmp_rules; tmp_rules=$(mktemp)
  {
    echo "table inet firewall-manager {"
    echo "  chain input {"
    echo "    type filter hook input priority 0; policy drop;"
    echo "    ct state { established, related } accept"
    echo "    iif lo accept"
    echo "    ct state invalid drop"
    for ip in "${BLOCKED_CLEAN[@]:-}"; do
      echo "    ip saddr ${ip} drop"
    done
    echo "    tcp dport ${ssh_port} accept"
    [[ -n "$tcp_ports" ]] && echo "    tcp dport { ${tcp_ports} } accept"
    [[ -n "$udp_ports" ]] && echo "    udp dport { ${udp_ports} } accept"
    echo "  }"
    echo
    echo "  chain forward {"
    echo "    type filter hook forward priority 0; policy drop;"
    # Only source-side drops here (cleaner output; still blocks spoofed scans)
    for ip in "${BLOCKED_CLEAN[@]:-}"; do
      echo "    ip saddr ${ip} drop"
    done
    echo "  }"
    echo
    echo "  chain output {"
    echo "    type filter hook output priority 0; policy accept;"
    for ip in "${BLOCKED_CLEAN[@]:-}"; do
      echo "    ip daddr ${ip} drop"
    done"
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

# ---------------- Menus & helpers ----------------
prompt_to_apply(){ apply_rules --no-pause; }  # used after blocklist update

parse_and_process_ports(){
  local action="$1" proto_file="$2" input_ports="$3"
  local count=0 ssh_port; ssh_port=$(detect_ssh_port)
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
        echo -e " -> ${GREEN}Port range $item processed.${NC}"
      else
        echo -e " -> ${RED}Invalid range: $item${NC}"
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "remove" && "$item" == "$ssh_port" && "$proto_file" == "$ALLOWED_TCP_PORTS_FILE" ]]; then
        echo -e " -> ${RED}Safety: Cannot remove SSH port (${ssh_port}).${NC}"; continue
      fi
      if [[ "$action" == "add" && "$item" == "$ssh_port" && "$proto_file" == "$ALLOWED_TCP_PORTS_FILE" ]]; then
        echo -e " -> ${YELLOW}SSH port is already allowed automatically.${NC}"; continue
      fi
      if [[ "$action" == "add" ]] && ! grep -q "^${item}$" "$proto_file"; then
        echo "$item" >> "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item added.${NC}"
      elif [[ "$action" == "add" ]]; then
        echo -e " -> ${YELLOW}Port $item already exists.${NC}"
      elif [[ "$action" == "remove" ]] && grep -q "^${item}$" "$proto_file"; then
        sed -i "/^${item}$/d" "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item removed.${NC}"
      else
        echo -e " -> ${YELLOW}Port $item not found.${NC}"
      fi
    elif [[ -n "$item" ]]; then
      echo -e " -> ${RED}Invalid input: $item${NC}"
    fi
  done
  echo "$count"
}

add_ports_interactive(){
  local proto="$1" no_prompt=${2:-""}
  local proto_file; [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
  if [[ "$no_prompt" != "--no-prompt" ]]; then
    while true; do
      clear; echo -e "${YELLOW}--- Add Allowed ${proto} Ports ---${NC}"
      echo "Current ${proto} ports: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
      read -r -p "Enter ${proto} port(s) to add (e.g., 80,443 or 1000-2000) or leave empty to go back: " input_ports < /dev/tty
      [[ -z "$input_ports" ]] && break
      local changed; changed=$(parse_and_process_ports "add" "$proto_file" "$input_ports")
      if (( changed > 0 )); then
        echo -e "${YELLOW}Applying firewall...${NC}"
        apply_rules --no-pause
      else
        echo "No changes."
      fi
      press_enter_to_continue
    done
  fi
}

remove_ports_interactive(){
  local proto="$1"
  local proto_file; [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
  while true; do
    clear; echo -e "${YELLOW}--- Remove Allowed ${proto} Ports ---${NC}"
    echo "Current ${proto} ports: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
    read -r -p "Enter ${proto} port(s) to remove (blank to go back): " input_ports < /dev/tty
    [[ -z "$input_ports" ]] && break
    local changed; changed=$(parse_and_process_ports "remove" "$proto_file" "$input_ports")
    if (( changed > 0 )); then
      echo -e "${YELLOW}Applying firewall...${NC}"
      apply_rules --no-pause
    else
      echo "No changes."
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
      1) add_ports_interactive "TCP" ;;
      2) remove_ports_interactive "TCP" ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
    esac
  done
}

manage_udp_ports_menu(){
  while true; do
    clear; echo "--- Manage Allowed UDP Ports ---"
    echo "1) Add UDP Port(s)"; echo "2) Remove UDP Port(s)"; echo "3) Back"
    read -r -p "Choose an option: " choice < /dev/tty
    case $choice in
      1) add_ports_interactive "UDP" ;;
      2) remove_ports_interactive "UDP" ;;
      3) break ;;
      *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
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

main_menu(){
  while true; do
    clear
    echo "==============================="
    echo " NFTABLES FIREWALL MANAGER v6.4"
    echo "==============================="
    echo "1) View Current Firewall Rules"
    echo "2) Apply Firewall Rules from Config"
    echo "3) Manage Allowed TCP Ports"
    echo "4) Manage Allowed UDP Ports"
    echo "5) Update IP Blocklist from Source"
    echo "6) Flush All Rules & Reset Config"
    echo "7) Uninstall Firewall & Script"
    echo "8) Exit"
    echo "-------------------------------"
    read -r -p "Choose an option: " choice < /dev/tty
    case $choice in
      1) view_rules ;;
      2) apply_rules ;;
      3) manage_tcp_ports_menu ;;
      4) manage_udp_ports_menu ;;
      5) update_blocklist; press_enter_to_continue ;;
      6) flush_rules ;;
      7) uninstall_script ;;
      8) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
    esac
  done
}

# --- SCRIPT START ---
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2
  exit 1
fi
prepare_system
initial_setup
main_menu
