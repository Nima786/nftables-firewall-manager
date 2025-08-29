#!/bin/bash

# =================================================================
#        Interactive IPTABLES Firewall Manager - v3.4 (Definitive)
# =================================================================
# A menu-driven utility to manage a robust iptables firewall.
# v3.4: Streamlined all edit functions to remove double prompts and
#       improve workflow consistency.

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

press_enter_to_continue() {
  echo ""
  read -r -p "Press Enter to return..."
}

# --- DEPENDENCY AND SETUP FUNCTIONS ---
check_dependencies() {
  echo -e "${YELLOW}Checking dependencies...${NC}"
  if ! command -v iptables &> /dev/null; then
    echo -e "${YELLOW}Dependency 'iptables' not found. Attempting to install...${NC}"
    apt-get update && apt-get install -y iptables
    if ! command -v iptables &> /dev/null; then
      echo -e "${RED}FATAL: Failed to install 'iptables'. Please install it manually.${NC}"
      exit 1
    fi
    echo -e "${GREEN}'iptables' installed successfully.${NC}"
  fi

  if ! command -v netfilter-persistent &> /dev/null; then
    echo -e "${YELLOW}Dependency 'iptables-persistent' not found. Attempting to install...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
    if ! command -v netfilter-persistent &> /dev/null; then
      echo -e "${RED}FATAL: Failed to install 'iptables-persistent'. Please install it manually.${NC}"
      exit 1
    fi
    echo -e "${GREEN}'iptables-persistent' installed successfully.${NC}"
  fi

  if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}Dependency 'curl' not found. Attempting to install...${NC}"
    apt-get update && apt-get install -y curl
    if ! command -v curl &> /dev/null; then
      echo -e "${RED}FATAL: Failed to install 'curl'. Please install it manually.${NC}"
      exit 1
    fi
    echo -e "${GREEN}'curl' installed successfully.${NC}"
  else
    echo -e "${GREEN}All dependencies are met.${NC}"
  fi
}

function update_blocklist() {
  local is_initial_setup=${1:-false}
  echo -e "${YELLOW}Attempting to download latest blocklist from source...${NC}"
  local temp_file
  temp_file=$(mktemp)
  if curl -sL "$BLOCKLIST_URL" -o "$temp_file"; then
    if [ -s "$temp_file" ] && [ "$(wc -l < "$temp_file")" -gt 10 ]; then
      sed -i 's/\r$//' "$temp_file"
      mv "$temp_file" "$BLOCKED_IPS_FILE"
      echo -e "${GREEN}Blocklist successfully downloaded and updated.${NC}"
      if [[ "$is_initial_setup" == false ]]; then
        prompt_to_apply
      fi
    else
      echo -e "${RED}Error: Downloaded file was empty or too small. Aborting update.${NC}"
      rm -f "$temp_file"; return 1
    fi
  else
    echo -e "${RED}Error: Failed to download the blocklist from the URL.${NC}"
    rm -f "$temp_file"; return 1
  fi
  return 0
}

create_default_blocked_ips_fallback() {
  cat > "$BLOCKED_IPS_FILE" << EOL
# FALLBACK LIST: Could not download from remote source.
10.0.0.0/8
100.64.0.0/10
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
198.18.0.0/15
EOL
}

initial_setup() {
  if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}First time setup: Creating configuration...${NC}"
    mkdir -p "$CONFIG_DIR"
    touch "$ALLOWED_TCP_PORTS_FILE" "$ALLOWED_UDP_PORTS_FILE"
    if ! update_blocklist true; then
      echo -e "${YELLOW}Using fallback blocklist...${NC}"
      create_default_blocked_ips_fallback
    fi
    echo -e "${YELLOW}Do you want to add initial allowed ports now?${NC}"
    read -r -p "Enter initial TCP ports to allow (e.g., 80, 443): " input_ports
    parse_and_process_ports add "$ALLOWED_TCP_PORTS_FILE" "$input_ports"
    echo -e "${YELLOW}Downloading/refreshing blocklist...${NC}"
    update_blocklist true
  fi
}

apply_rules() {
  local no_pause=false
  if [[ "$1" == "--no-pause" ]]; then no_pause=true; fi

  echo "[+] Flushing old rules..."
  iptables -F; iptables -X
  iptables -N abuse-defender

  echo "[+] Populating the abuse-defender IP blocklist..."
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    iptables -A abuse-defender -d "$line" -j DROP
  done < "$BLOCKED_IPS_FILE"

  echo "[+] Setting default policies..."
  iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT

  echo "[+] Allowing core traffic..."
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  echo "[+] Applying HARDCODED SSH port rule (Port ${SSH_PORT} - keep open for remote admin)..."
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT

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

  echo "[+] Activating 3-layer blocklist protection..."
  iptables -I INPUT 1 -j abuse-defender
  iptables -I FORWARD 1 -j abuse-defender
  iptables -I OUTPUT 1 -j abuse-defender

  # Docker chain (if present)
  if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    echo "[+] Docker detected. Applying Docker-specific rule..."
    iptables -I DOCKER-USER 1 -j abuse-defender
  fi

  echo -e "\n${YELLOW}Saving rules to make them persistent...${NC}"
  netfilter-persistent save

  echo -e "\n${GREEN}Firewall configuration applied and saved successfully!${NC}"
  if [[ "$no_pause" == false ]]; then press_enter_to_continue; fi
}

prompt_to_apply() {
  echo ""
  read -r -p "Apply these changes now to make them live? (y/n): " confirm
  if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    apply_rules --no-pause
  else
    echo -e "${YELLOW}Changes saved to config but NOT applied.${NC}"
  fi
}

parse_and_process_ports() {
  local action="$1"; local proto_file="$2"; local input_ports="$3"
  local count=0
  IFS=',' read -ra port_items <<< "$input_ports"
  for item in "${port_items[@]}"; do
    item=$(echo "$item" | xargs)
    if [[ "$item" == *-* ]]; then
      local start_port
      start_port=$(echo "$item" | cut -d'-' -f1)
      local end_port
      end_port=$(echo "$item" | cut -d'-' -f2)
      if [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ && "$start_port" -le "$end_port" ]]; then
        for ((port=start_port; port<=end_port; port++)); do
          if [[ "$action" == "remove" && "$port" == "$SSH_PORT" ]]; then continue; fi
          if [[ "$action" == "add" ]] && ! grep -q "^${port}$" "$proto_file"; then
            echo "$port" >> "$proto_file"; ((count++))
          elif [[ "$action" == "remove" ]] && grep -q "^${port}$" "$proto_file"; then
            sed -i "/^${port}$/d" "$proto_file"; ((count++))
          fi
        done
        echo -e " -> ${GREEN}Port range $item processed.${NC}"
      else
        echo -e " -> ${RED}Invalid range: $item${NC}"
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      if [[ "$action" == "remove" && "$item" == "$SSH_PORT" ]]; then
        echo -e " -> ${YELLOW}Protective: Cannot remove SSH port (${SSH_PORT}).${NC}"
        continue
      fi
      if [[ "$action" == "add" ]] && ! grep -q "^${item}$" "$proto_file"; then
        echo "$item" >> "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item added.${NC}"
      elif [[ "$action" == "add" ]]; then
        echo -e " -> ${YELLOW}Port $item already exists.${NC}"
      elif [[ "$action" == "remove" ]] && grep -q "^${item}$" "$proto_file"; then
        sed -i "/^${item}$/d" "$proto_file"; ((count++)); echo -e " -> ${GREEN}Port $item removed.${NC}"
      else
        echo -e " -> ${YELLOW}Port $item not found in config.${NC}"
      fi
    elif [[ -n "$item" ]]; then
      echo -e " -> ${RED}Invalid input: $item${NC}"
    fi
  done

  if [ "$count" -gt 0 ]; then
    echo -e "\n${GREEN}Configuration updated (${count} change(s)).${NC}"
    prompt_to_apply
  else
    echo -e "\nNo changes were made."
  fi
}

manage_ports_interactive() {
  local action="$1"; local proto="$2"; local proto_file=""
  if [[ "$proto" == "TCP" ]]; then proto_file="$ALLOWED_TCP_PORTS_FILE"; else proto_file="$ALLOWED_UDP_PORTS_FILE"; fi
  clear
  echo -e "${YELLOW}--- ${action^} Allowed ${proto} Ports ---${NC}"
  echo -n "Current ${proto} ports: "
  sort -n "$proto_file" | uniq | paste -s -d, || echo "None"
  echo ""
  read -r -p "Enter ${proto} port(s) to ${action} (e.g., 80, 443, 1000-2000): " input_ports
  parse_and_process_ports "$action" "$proto_file" "$input_ports"
}

view_rules() {
  clear
  echo -e "${YELLOW}--- Current IPTABLES Rules ---${NC}"
  iptables -L -n -v --line-numbers
  press_enter_to_continue
}

manage_tcp_ports_menu() {
  while true; do
    clear
    echo "--- Manage Allowed TCP Ports ---"
    echo "1) Add TCP Port(s)"
    echo "2) Remove TCP Port(s)"
    echo "3) Back"
    read -r -p "Choose an option: " choice
    case "$choice" in
      1) manage_ports_interactive add "TCP" ;;
      2) manage_ports_interactive remove "TCP" ;;
      3) break ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

manage_udp_ports_menu() {
  while true; do
    clear
    echo "--- Manage Allowed UDP Ports ---"
    echo "1) Add UDP Port(s)"
    echo "2) Remove UDP Port(s)"
    echo "3) Back"
    read -r -p "Choose an option: " choice
    case "$choice" in
      1) manage_ports_interactive add "UDP" ;;
      2) manage_ports_interactive remove "UDP" ;;
      3) break ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

edit_list_item() {
  local item_type="$1"; local file="$2"
  echo ""
  read -r -p "Enter the new ${item_type} to add: " item
  [[ -z "$item" ]] && echo "No input." && return
  if ! grep -qxF "$item" "$file" 2>/dev/null; then
    echo "$item" >> "$file"; echo "Added: $item"
    prompt_to_apply
  else
    echo "Already present: $item"
  fi
}

remove_list_item() {
  local item_type="$1"; local file="$2"
  echo ""
  read -r -p "Enter the ${item_type} to remove: " item
  [[ -z "$item" ]] && echo "No input." && return
  if grep -qxF "$item" "$file" 2>/dev/null; then
    local temp_file
    temp_file=$(mktemp)
    grep -vFx "$item" "$file" > "$temp_file"
    mv "$temp_file" "$file"
    echo "Removed: $item"
    prompt_to_apply
  else
    echo "Not found: $item"
  fi
}

manage_blocklist_menu() {
  while true; do
    clear
    echo "--- Manage Blocked IPs ---"
    echo "1) Add IP/CIDR"
    echo "2) Remove IP/CIDR"
    echo "3) Back"
    read -r -p "Choose an option: " choice
    case "$choice" in
      1) edit_list_item "IP/CIDR" "$BLOCKED_IPS_FILE" ;;
      2) remove_list_item "IP/CIDR" "$BLOCKED_IPS_FILE" ;;
      3) break ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

reset_and_recreate_config() {
  clear
  read -r -p "ARE YOU SURE? This will flush all rules and reset the configuration. (y/n): " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then return; fi

  iptables -F; iptables -X
  echo -e "${YELLOW}Reset complete. Creating a fresh configuration...${NC}"
  rm -rf "$CONFIG_DIR"
  mkdir -p "$CONFIG_DIR"
  touch "$ALLOWED_TCP_PORTS_FILE" "$ALLOWED_UDP_PORTS_FILE" "$BLOCKED_IPS_FILE"

  local input_ports
  read -r -p "Enter initial TCP ports to allow (e.g., 80, 443): " input_ports
  parse_and_process_ports add "$ALLOWED_TCP_PORTS_FILE" "$input_ports"
  update_blocklist true
}

uninstall_everything() {
  clear
  echo -e "${RED}--- UNINSTALL FIREWALL & SCRIPT ---${NC}"
  read -r -p "ARE YOU SURE you want to permanently delete the firewall and this script? (y/n): " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then return; fi

  echo "[+] Flushing iptables and deleting chains..."
  iptables -F; iptables -X
  iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT

  echo "[+] Removing configuration directory $CONFIG_DIR ..."
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
    read -r -p "Choose an option: " choice
    case "$choice" in
      1) view_rules ;;
      2) apply_rules ;;
      3) manage_tcp_ports_menu ;;
      4) manage_udp_ports_menu ;;
      5) manage_blocklist_menu ;;
      6) update_blocklist ;;
      7) reset_and_recreate_config ;;
      8) uninstall_everything ;;
      9|0) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
  done
}

# --- SCRIPT START ---
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2
  exit 1
fi
check_dependencies
initial_setup
main_menu
