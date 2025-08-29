#!/bin/bash
# Make interactive prompts work even when the script is piped (curl | bash)
if [ ! -t 0 ] && [ -e /dev/tty ]; then exec </dev/tty; fi

# =================================================================
#        Interactive IPTABLES Firewall Manager - v3.4 (Fixed)
# =================================================================

# --- CONFIGURATION ---
CONFIG_DIR="/etc/firewall_manager"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
SSH_PORT="22" # Hardcoded for safety
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# --- COLORS ---
RED="\033[0;31m"
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
NC="\033[0m"

press_enter_to_continue() { echo ""; read -r -p "Press Enter to return..."; }

# ----------------- DEPENDENCIES -----------------
check_dependencies() {
  echo -e "${YELLOW}Checking dependencies...${NC}"

  if ! command -v iptables &>/dev/null; then
    echo -e "${YELLOW}Installing iptables...${NC}"
    apt-get update && apt-get install -y iptables
    command -v iptables &>/dev/null || { echo -e "${RED}Failed to install iptables${NC}"; exit 1; }
  fi

  if ! command -v netfilter-persistent &>/dev/null; then
    echo -e "${YELLOW}Installing iptables-persistent...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
    command -v netfilter-persistent &>/dev/null || { echo -e "${RED}Failed to install iptables-persistent${NC}"; exit 1; }
  fi

  if ! command -v curl &>/dev/null; then
    echo -e "${YELLOW}Installing curl...${NC}"
    apt-get update && apt-get install -y curl
    command -v curl &>/dev/null || { echo -e "${RED}Failed to install curl${NC}"; exit 1; }
  fi

  echo -e "${GREEN}All dependencies are met.${NC}"
}

# ----------------- BLOCKLIST -----------------
update_blocklist() {
  local is_initial_setup=${1:-false}
  echo -e "${YELLOW}Attempting to download latest blocklist from source...${NC}"
  local tmp
  tmp=$(mktemp)

  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
    if [ -s "$tmp" ] && [ "$(wc -l < "$tmp")" -gt 10 ]; then
      sed -i 's/\r$//' "$tmp"
      mv "$tmp" "$BLOCKED_IPS_FILE"
      echo -e "${GREEN}Blocklist successfully downloaded and updated.${NC}"
      [[ "$is_initial_setup" == false ]] && prompt_to_apply
    else
      echo -e "${RED}Downloaded blocklist is empty/suspicious; keeping previous file.${NC}"
      rm -f "$tmp"; return 1
    fi
  else
    echo -e "${RED}Failed to download blocklist from source.${NC}"
    rm -f "$tmp"; return 1
  fi
}

create_default_blocked_ips_fallback() {
  cat >"$BLOCKED_IPS_FILE" <<'EOL'
# FALLBACK LIST: Could not download from remote source.
10.0.0.0/8
100.64.0.0/10
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
198.18.0.0/15
EOL
}

# ----------------- FIRST-RUN SETUP -----------------
initial_setup() {
  if [ -d "$CONFIG_DIR" ]; then return; fi

  echo -e "${YELLOW}First time setup: Creating configuration...${NC}"
  mkdir -p "$CONFIG_DIR"
  : >"$ALLOWED_TCP_PORTS_FILE"
  : >"$ALLOWED_UDP_PORTS_FILE"

  if ! update_blocklist true; then
    echo -e "${YELLOW}Using fallback blocklist...${NC}"
    create_default_blocked_ips_fallback
  fi

  echo -e "${YELLOW}Do you want to add initial allowed ports now?${NC}"
  read -r -p "Enter initial TCP ports (e.g., 80,443) or press Enter to skip: " input_ports
  if [ -n "$input_ports" ]; then
    parse_and_process_ports add "$ALLOWED_TCP_PORTS_FILE" "$input_ports"
  else
    echo "No ports entered, skipping..."
  fi

  echo -e "${YELLOW}Downloading/refreshing blocklist...${NC}"
  update_blocklist true >/dev/null 2>&1 || true
}

# ----------------- APPLY RULES -----------------
apply_rules() {
  local no_pause=false
  [[ "$1" == "--no-pause" ]] && no_pause=true

  echo "[+] Flushing old rules..."
  iptables -F; iptables -X

  echo "[+] Creating blocklist chain..."
  iptables -N abuse-defender 2>/dev/null || true

  echo "[+] Populating the abuse-defender IP blocklist..."
  if [ -f "$BLOCKED_IPS_FILE" ]; then
    while IFS= read -r line; do
      [[ -z "$line" || "$line" =~ ^# ]] && continue
      iptables -A abuse-defender -s "$line" -j DROP
    done <"$BLOCKED_IPS_FILE"
  fi

  echo "[+] Setting default policies..."
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  echo "[+] Allowing loopback and established connections..."
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  echo "[+] Keeping SSH open on port ${SSH_PORT}..."
  iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

  echo "[+] Allowing configured TCP ports..."
  sort -u "$ALLOWED_TCP_PORTS_FILE" 2>/dev/null | while IFS= read -r port; do
    [[ -z "$port" || "$port" == "$SSH_PORT" ]] && continue
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  done

  echo "[+] Allowing configured UDP ports..."
  sort -u "$ALLOWED_UDP_PORTS_FILE" 2>/dev/null | while IFS= read -r port; do
    [[ -z "$port" ]] && continue
    iptables -A INPUT -p udp --dport "$port" -j ACCEPT
  done

  echo "[+] Activating blocklist chain..."
  iptables -I INPUT 1 -j abuse-defender
  iptables -I FORWARD 1 -j abuse-defender
  iptables -I OUTPUT 1 -j abuse-defender

  # If Docker chain exists, protect it as well
  if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    echo "[+] Docker detected. Applying Docker-specific rule..."
    iptables -I DOCKER-USER 1 -j abuse-defender
  fi

  echo -e "\n${YELLOW}Saving rules to make them persistent...${NC}"
  netfilter-persistent save

  echo -e "\n${GREEN}Firewall configuration applied and saved successfully!${NC}"
  [[ "$no_pause" == false ]] && press_enter_to_continue
}

prompt_to_apply() {
  echo ""
  read -r -p "Apply these changes now to make them live? (y/n): " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    apply_rules --no-pause
  else
    echo -e "${YELLOW}Changes saved to config but NOT applied.${NC}"
  fi
}

# ----------------- PORT HELPERS -----------------
parse_and_process_ports() {
  local action="$1"; local file="$2"; local input="$3"
  local count=0
  IFS=',' read -ra items <<<"$input"
  for item in "${items[@]}"; do
    item=$(echo "$item" | xargs)
    [[ -z "$item" ]] && continue

    if [[ "$item" == *-* ]]; then
      local s e
      s=$(echo "$item" | cut -d'-' -f1)
      e=$(echo "$item" | cut -d'-' -f2)
      if [[ "$s" =~ ^[0-9]+$ && "$e" =~ ^[0-9]+$ && "$s" -le "$e" ]]; then
        for ((p=s; p<=e; p++)); do
          [[ "$action" == "remove" && "$p" == "$SSH_PORT" ]] && continue
          if [[ "$action" == "add" ]] && ! grep -qxF "$p" "$file" 2>/dev/null; then echo "$p" >>"$file"; ((count++)); fi
          if [[ "$action" == "remove" ]] && grep -qxF "$p" "$file" 2>/dev/null; then sed -i "/^${p}\$/d" "$file"; ((count++)); fi
        done
        echo " -> Range $item processed."
      else
        echo " -> Invalid range: $item"
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "remove" && "$item" == "$SSH_PORT" ]]; then
        echo " -> Protective: cannot remove SSH port ($SSH_PORT)."; continue
      fi
      if [[ "$action" == "add" ]] && ! grep -qxF "$item" "$file" 2>/dev/null; then echo "$item" >>"$file"; ((count++)); echo " -> Port $item added."; fi
      if [[ "$action" == "remove" ]] && grep -qxF "$item" "$file" 2>/dev/null; then sed -i "/^${item}\$/d" "$file"; ((count++)); echo " -> Port $item removed."; fi
    else
      echo " -> Invalid input: $item"
    fi
  done

  if [ "$count" -gt 0 ]; then
    echo -e "${GREEN}${count} change(s) saved.${NC}"
    prompt_to_apply
  else
    echo "No changes were made."
  fi
}

manage_ports_interactive() {
  local action="$1"; local proto="$2"; local file
  file="$ALLOWED_TCP_PORTS_FILE"; [[ "$proto" == "UDP" ]] && file="$ALLOWED_UDP_PORTS_FILE"

  clear
  echo -e "${YELLOW}--- ${action^} Allowed ${proto} Ports ---${NC}"
  echo -n "Current ${proto} ports: "
  sort -n "$file" 2>/dev/null | uniq | paste -s -d, || echo "None"
  echo ""
  read -r -p "Enter ${proto} port(s) to ${action} (e.g., 80,443,1000-2000): " in
  parse_and_process_ports "$action" "$file" "$in"
}

# ----------------- MENUS -----------------
view_rules() { clear; echo -e "${YELLOW}--- Current IPTABLES Rules ---${NC}"; iptables -L -n -v --line-numbers; press_enter_to_continue; }

edit_list_item()   { local t="$1" f="$2"; echo ""; read -r -p "Enter the new ${t} to add: " x; [[ -z "$x" ]] && { echo "No input."; return; }; grep -qxF "$x" "$f" 2>/dev/null || { echo "$x" >>"$f"; echo "Added: $x"; prompt_to_apply; }; }
remove_list_item() {
  local t="$1" f="$2"; echo ""; read -r -p "Enter the ${t} to remove: " x; [[ -z "$x" ]] && { echo "No input."; return; }
  if grep -qxF "$x" "$f" 2>/dev/null; then local tmp; tmp=$(mktemp); grep -vFx "$x" "$f" >"$tmp"; mv "$tmp" "$f"; echo "Removed: $x"; prompt_to_apply; else echo "Not found: $x"; fi
}

manage_blocklist_menu() {
  while true; do
    clear; echo "--- Manage Blocked IPs ---"; echo "1) Add IP/CIDR"; echo "2) Remove IP/CIDR"; echo "3) Back"
    read -r -p "Choose an option: " c
    case "$c" in
      1) edit_list_item "IP/CIDR" "$BLOCKED_IPS_FILE" ;;
      2) remove_list_item "IP/CIDR" "$BLOCKED_IPS_FILE" ;;
      3) break ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

reset_and_recreate_config() {
  clear; read -r -p "ARE YOU SURE? This will flush all rules and reset the configuration. (y/n): " y
  [[ "$y" =~ ^[Yy]$ ]] || return
  iptables -F; iptables -X
  echo -e "${YELLOW}Reset complete. Creating a fresh configuration...${NC}"
  rm -rf "$CONFIG_DIR"; mkdir -p "$CONFIG_DIR"
  : >"$ALLOWED_TCP_PORTS_FILE"; : >"$ALLOWED_UDP_PORTS_FILE"; : >"$BLOCKED_IPS_FILE"
  local in; read -r -p "Enter initial TCP ports to allow (e.g., 80,443) or press Enter to skip: " in
  [[ -n "$in" ]] && parse_and_process_ports add "$ALLOWED_TCP_PORTS_FILE" "$in"
  update_blocklist true || true
}

uninstall_everything() {
  clear; echo -e "${RED}--- UNINSTALL FIREWALL & SCRIPT ---${NC}"
  read -r -p "ARE YOU SURE you want to permanently delete the firewall and this script? (y/n): " y
  [[ "$y" =~ ^[Yy]$ ]] || return
  iptables -F; iptables -X
  iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
  rm -rf "$CONFIG_DIR"
  echo -e "${GREEN}Uninstall complete.${NC}"
  press_enter_to_continue
}

main_menu() {
  while true; do
    clear
    echo "==============================="
    echo "   IPTABLES FIREWALL MANAGER v3.4"
    echo "==============================="
    echo "1) View Current Firewall Rules"
    echo "2) Apply Firewall Rules from Config"
    echo "3) Manage Allowed TCP Ports"
    echo "4) Manage Allowed UDP Ports"
    echo "5) Manage Blocked IPs"
    echo "6) Update IP Blocklist from Source"
    echo "7) Flush & Reset Configuration"
    echo "8) Uninstall Firewall & Script"
    echo "9) Exit"
    echo "-------------------------------"
    read -r -p "Choose an option: " c
    case "$c" in
      1) view_rules ;;
      2) apply_rules ;;
      3) manage_ports_interactive add "TCP" ;;
      4) manage_ports_interactive add "UDP" ;;
      5) manage_blocklist_menu ;;
      6) update_blocklist ;;
      7) reset_and_recreate_config ;;
      8) uninstall_everything ;;
      9|0) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

# ----------------- ENTRY -----------------
if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2; exit 1; fi
check_dependencies
initial_setup
main_menu
