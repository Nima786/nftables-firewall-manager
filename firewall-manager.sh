#!/bin/bash
set -euo pipefail

# ======================================================
#   IPTABLES Firewall Manager – unattended + interactive
# ======================================================

# -------------------- PATHS --------------------
CONFIG_DIR="/etc/firewall_manager"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
SAVED_SCRIPT="$CONFIG_DIR/firewall-manager.sh"     # offline saved copy
LAUNCHER="/usr/local/bin/firewall-manager"         # user command
SSH_PORT="22"

# Remote URLs
SCRIPT_URL="https://raw.githubusercontent.com/Nima786/iptables-firewall-manager/main/firewall-manager.sh"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# Colors
RED="\033[0;31m"; YELLOW="\033[1;33m"; GREEN="\033[0;32m"; NC="\033[0m"

# Detect if stdin is a pipe (one-liner install)
PIPED=false; [ ! -t 0 ] && PIPED=true

# Internal switches (the launcher passes --menu; users never type flags)
FORCE_MENU=false
for a in "${@:-}"; do
  case "$a" in
    --menu) FORCE_MENU=true ;;
  esac
done

# -------------------- HELPERS --------------------
press_enter() { echo; read -r -p "Press Enter to return..."; }
need_bin() { command -v "$1" &>/dev/null; }
install_pkgs() {
  echo -e "${YELLOW}Installing missing packages (requires apt) ...${NC}"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}
dos2unix_inplace() { sed -i 's/\r$//' "$1"; }
normalize_ip_token() {
  local t="$1"
  t="${t//$'\r'/}"            # strip CR
  t="${t%%#*}"                # strip comment
  t="${t%% *}"; t="${t%%,*}"; t="${t%%;*}"
  t="$(echo "$t" | xargs)"    # trim
  printf '%s' "$t"
}
is_valid_ipv4_or_cidr() {
  local r='^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$'
  [[ "$1" =~ $r ]]
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
    dos2unix_inplace "$tmp"
    mv "$tmp" "$BLOCKED_IPS_FILE"
    echo -e "${GREEN}Blocklist updated (${BLOCKED_IPS_FILE}).${NC}"
  else
    echo -e "${RED}Blocklist download failed; using fallback list.${NC}"
    rm -f "$tmp" || true
    fallback_blocklist
  fi
}

# -------------------- CONFIG --------------------
initial_setup_noninteractive() {
  echo -e "${YELLOW}Setting up configuration in ${CONFIG_DIR}...${NC}"
  mkdir -p "$CONFIG_DIR"
  : >"$ALLOWED_TCP_PORTS_FILE"
  : >"$ALLOWED_UDP_PORTS_FILE"
  update_blocklist
}

# -------------------- RULES --------------------
apply_rules() {
  echo "[+] Flushing existing rules..."
  iptables -F || true; iptables -X || true

  echo "[+] Creating blocklist chain..."
  iptables -N abuse-defender 2>/dev/null || true

  echo "[+] Loading blocklist..."
  if [ -f "$BLOCKED_IPS_FILE" ]; then
    dos2unix_inplace "$BLOCKED_IPS_FILE"
    while IFS= read -r raw; do
      [[ -z "$raw" || "$raw" =~ ^[[:space:]]*# ]] && continue
      ip="$(normalize_ip_token "$raw")"
      [[ -z "$ip" ]] && continue
      if is_valid_ipv4_or_cidr "$ip"; then
        iptables -A abuse-defender -s "$ip" -j DROP || true
      fi
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

  if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    echo "[+] Docker detected: applying blocklist to DOCKER-USER"
    iptables -I DOCKER-USER 1 -j abuse-defender
  fi

  echo "[+] Persisting rules..."
  netfilter-persistent save
  echo -e "${GREEN}Firewall rules applied & saved.${NC}"
}

# -------------------- INTERACTIVE (MENU) --------------------
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
  iptables -F || true; iptables -X || true
  rm -rf "$CONFIG_DIR"; mkdir -p "$CONFIG_DIR"
  : >"$ALLOWED_TCP_PORTS_FILE"; : >"$ALLOWED_UDP_PORTS_FILE"; : >"$BLOCKED_IPS_FILE"
  update_blocklist
  echo "Reset done."; press_enter
}

uninstall_all(){
  clear
  read -r -p "Uninstall firewall & remove config? (y/n): " y
  [[ "$y" =~ ^[Yy]$ ]] || return
  iptables -F || true; iptables -X || true
  iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
  rm -rf "$CONFIG_DIR" "$SAVED_SCRIPT"
  rm -f "$LAUNCHER"
  echo "Uninstalled."
  press_enter
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

# -------------------- INSTALL LAUNCHER --------------------
install_launcher_and_save_copy() {
  mkdir -p "$CONFIG_DIR"
  # Save offline copy of the current script from canonical URL
  if curl -fsSL "$SCRIPT_URL" -o "$SAVED_SCRIPT"; then
    chmod +x "$SAVED_SCRIPT"
  fi

  # Create launcher that always opens the menu
  cat >"$LAUNCHER" <<EOF
#!/bin/sh
# Launcher for interactive menu
exec sudo bash "$SAVED_SCRIPT" --menu
EOF
  chmod +x "$LAUNCHER"

  echo -e "${GREEN}Installed launcher: $LAUNCHER${NC}"
  echo "Tip: run 'sudo firewall-manager' to manage the firewall."
}

# -------------------- ENTRY --------------------
if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}Run as root (use sudo).${NC}" >&2; exit 1; fi
check_dependencies

# If piped and already installed, jump straight to the menu via launcher
if $PIPED && [ -x "$LAUNCHER" ]; then
  exec "$LAUNCHER"
fi

# First-time unattended install when piped:
if $PIPED && [ ! -d "$CONFIG_DIR" ]; then
  echo -e "${YELLOW}[AUTO] Non-interactive install: setting up and applying rules...${NC}"
  initial_setup_noninteractive
  apply_rules
  install_launcher_and_save_copy
  exit 0
fi

# If called with --menu (by our launcher), open the interactive menu
if $FORCE_MENU; then
  # ensure files exist
  mkdir -p "$CONFIG_DIR"
  touch "$ALLOWED_TCP_PORTS_FILE" "$ALLOWED_UDP_PORTS_FILE" "$BLOCKED_IPS_FILE" || true
  main_menu
  exit 0
fi

# Otherwise (run directly in a TTY): show menu
mkdir -p "$CONFIG_DIR"
touch "$ALLOWED_TCP_PORTS_FILE" "$ALLOWED_UDP_PORTS_FILE" "$BLOCKED_IPS_FILE" || true
main_menu
