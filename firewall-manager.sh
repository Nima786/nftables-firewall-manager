#!/bin/bash
set -euo pipefail

# -------------------- SETTINGS --------------------
CONFIG_DIR="/etc/firewall_manager"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
SSH_PORT="22"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# Colors
RED="\033[0;31m"; YELLOW="\033[1;33m"; GREEN="\033[0;32m"; NC="\033[0m"

# Mode
AUTO=false
for a in "$@"; do
  case "$a" in
    --auto|--yes|-y) AUTO=true ;;
  esac
done
# If piped (no TTY), default to AUTO to avoid hangs
if [ ! -t 0 ]; then AUTO=true; fi

# -------------------- HELPERS --------------------
press_enter() {
  if $AUTO; then
    return
  else
    echo
    read -r -p "Press Enter to return..."
  fi
}

need_bin() { command -v "$1" &>/dev/null; }
install_pkgs() {
  echo -e "${YELLOW}Installing missing packages (requires apt) ...${NC}"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

# -------------------- DEPENDENCIES --------------------
check_dependencies() {
  echo -e "${YELLOW}Checking dependencies...${NC}"
  need_bin iptables || install_pkgs iptables
  need_bin netfilter-persistent || install_pkgs iptables-persistent netfilter-persistent
  need_bin curl || install_pkgs curl
  echo -e "${GREEN}All dependencies are met.${NC}"
}

# -------------------- BLOCKLIST --------------------
fallback_blocklist() {
  cat >"$BLOCKED_IPS_FILE" <<'EOL'
# Fallback private/reserved ranges (example)
10.0.0.0/8
100.64.0.0/10
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
198.18.0.0/15
EOL
}

update_blocklist() {
  echo -e "${YELLOW}Fetching blocklist...${NC}"
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$BLOCKLIST_URL" -o "$tmp" && [ -s "$tmp" ] && [ "$(wc -l <"$tmp")" -gt 10 ]; then
    sed -i 's/\r$//' "$tmp"
    mv "$tmp" "$BLOCKED_IPS_FILE"
    echo -e "${GREEN}Blocklist updated (${BLOCKED_IPS_FILE}).${NC}"
  else
    echo -e "${RED}Blocklist download failed; using fallback list.${NC}"
    rm -f "$tmp" || true
    fallback_blocklist
  fi
}

# -------------------- CONFIG --------------------
initial_setup() {
  if [ -d "$CONFIG_DIR" ]; then return; fi
  echo -e "${YELLOW}Setting up configuration in ${CONFIG_DIR}...${NC}"
  mkdir -p "$CONFIG_DIR"
  : >"$ALLOWED_TCP_PORTS_FILE"
  : >"$ALLOWED_UDP_PORTS_FILE"
  update_blocklist

  if $AUTO; then
    echo -e "${YELLOW}[AUTO] Skipping initial ports prompt.${NC}"
  else
    echo -e "${YELLOW}Add initial allowed TCP ports (comma-separated, e.g. 80,443). Leave empty to skip.${NC}"
    read -r -p "Ports: " ports
    if [ -n "$ports" ]; then add_ports "$ALLOWED_TCP_PORTS_FILE" "$ports"; fi
  fi
}

# -------------------- RULES --------------------
apply_rules() {
  echo "[+] Flushing existing rules..."
  iptables -F; iptables -X || true

  # chain for blocklist
  iptables -N abuse-defender 2>/dev/null || true
  echo "[+] Loading blocklist..."
  if [ -f "$BLOCKED_IPS_FILE" ]; then
    while IFS= read -r ip; do
      [[ -z "$ip" || "$ip" =~ ^# ]] && continue
      iptables -A abuse-defender -s "$ip" -j DROP
    done <"$BLOCKED_IPS_FILE"
  fi

  echo "[+] Default policies..."
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  echo "[+] Allow loopback & established..."
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  echo "[+] Keep SSH (${SSH_PORT}/tcp) open..."
  iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

  echo "[+] Allow configured TCP ports..."
  sort -u "$ALLOWED_TCP_PORTS_FILE" 2>/dev/null | while IFS= read -r p; do
    [ -n "$p" ] && [ "$p" != "$SSH_PORT" ] && iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
  done

  echo "[+] Allow configured UDP ports..."
  sort -u "$ALLOWED_UDP_PORTS_FILE" 2>/dev/null | while IFS= read -r p; do
    [ -n "$p" ] && iptables -A INPUT -p udp --dport "$p" -j ACCEPT
  done

  echo "[+] Activate blocklist chain..."
  iptables -I INPUT 1 -j abuse-defender
  iptables -I FORWARD 1 -j abuse-defender
  iptables -I OUTPUT 1 -j abuse-defender

  # If Docker chain exists, protect it too
  if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    echo "[+] Docker detected: applying blocklist to DOCKER-USER"
    iptables -I DOCKER-USER 1 -j abuse-defender
  fi

  echo "[+] Persisting rules..."
  netfilter-persistent save
  echo -e "${GREEN}Firewall rules applied & saved.${NC}"
}

# -------------------- PORT HELPERS --------------------
add_ports() {
  local file="$1"; local input="$2"
  IFS=',' read -ra items <<<"$input"
  for item in "${items[@]}"; do
    item="$(echo "$item" | xargs)"
    [ -z "$item" ] && continue
    if [[ "$item" == *-* ]]; then
      local s e; s="${item%-*}"; e="${item#*-}"
      if [[ "$s" =~ ^[0-9]+$ && "$e" =~ ^[0-9]+$ && "$s" -le "$e" ]]; then
        for ((p=s; p<=e; p++)); do
          [ "$p" = "$SSH_PORT" ] && continue
          grep -qxF "$p" "$file" 2>/dev/null || echo "$p" >>"$file"
        done
      fi
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      [ "$item" = "$SSH_PORT" ] && continue
      grep -qxF "$item" "$file" 2>/dev/null || echo "$item" >>"$file"
    fi
  done
}

# -------------------- MENUS (interactive mode only) --------------------
view_rules(){ clear; iptables -L -n -v --line-numbers; press_enter; }
manage_ports_interactive(){
  local proto="$1" file
  file="$ALLOWED_TCP_PORTS_FILE"; [ "$proto" = "UDP" ] && file="$ALLOWED_UDP_PORTS_FILE"
  clear
  echo "Current $proto ports: $(sort -n "$file" 2>/dev/null | paste -s -d,)"
  read -r -p "Enter ${proto} ports to add (e.g., 80,443 or 1000-2000): " s
  [ -n "$s" ] && add_ports "$file" "$s"
  echo "Saved."
  press_enter
}
update_blocklist_menu(){ update_blocklist; press_enter; }

reset_config(){
  clear
  read -r -p "This will flush rules and reset config. Continue? (y/n): " y
  [[ "$y" =~ ^[Yy]$ ]] || return
  iptables -F; iptables -X || true
  rm -rf "$CONFIG_DIR"; mkdir -p "$CONFIG_DIR"
  : >"$ALLOWED_TCP_PORTS_FILE"; : >"$ALLOWED_UDP_PORTS_FILE"; : >"$BLOCKED_IPS_FILE"
  update_blocklist
  echo "Reset done."; press_enter
}

uninstall_all(){
  clear
  read -r -p "Uninstall firewall & remove config? (y/n): " y
  [[ "$y" =~ ^[Yy]$ ]] || return
  iptables -F; iptables -X || true
  iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
  rm -rf "$CONFIG_DIR"
  echo "Uninstalled."; press_enter
}

main_menu(){
  while true; do
    clear
    cat <<MENU
===============================
  IPTABLES FIREWALL MANAGER
===============================
1) View current firewall rules
2) Apply rules from config
3) Add allowed TCP ports
4) Add allowed UDP ports
5) Update IP blocklist
6) Flush & reset configuration
7) Uninstall firewall & script
9) Exit
-------------------------------
MENU
    read -r -p "Choose an option: " c
    case "$c" in
      1) view_rules ;;
      2) apply_rules ;;
      3) manage_ports_interactive TCP ;;
      4) manage_ports_interactive UDP ;;
      5) update_blocklist_menu ;;
      6) reset_config ;;
      7) uninstall_all ;;
      9|0) exit 0 ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

# -------------------- ENTRY --------------------
if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}Run as root (use sudo).${NC}" >&2; exit 1; fi
check_dependencies
initial_setup

if $AUTO; then
  echo -e "${YELLOW}[AUTO] Non-interactive install: applying rules now...${NC}"
  apply_rules
  exit 0
fi

main_menu
