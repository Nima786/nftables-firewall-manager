#!/bin/bash
set -euo pipefail

# =================================================================
#  Interactive NFTABLES Firewall Manager - v5.8
# =================================================================
# - Detects SSH port and adds to config automatically
# - Updates system and ensures dependencies (nftables, curl)
# - Robust to empty config files with set -euo pipefail
# - Proper blocklist enforcement using a named set
# - --no-prompt respected during initial setup

# --- CONFIGURATION ---
CONFIG_DIR="/etc/firewall_manager_nft"
ALLOWED_TCP_PORTS_FILE="$CONFIG_DIR/allowed_tcp_ports.conf"
ALLOWED_UDP_PORTS_FILE="$CONFIG_DIR/allowed_udp_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# Set to "true" to run apt upgrade during dependency check
UPDATE_SYSTEM="true"

# --- COLORS ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- HELPER FUNCTIONS ---
press_enter_to_continue() { echo ""; read -r -p "Press Enter to return..." < /dev/tty; }

# --- SYSTEM UPDATE & DEPENDENCIES ---
check_dependencies() {
    echo "[+] Checking/Updating system & dependencies..."
    export DEBIAN_FRONTEND=noninteractive

    # Always apt-get update; optional upgrade
    apt-get update -y >/dev/null
    if [[ "${UPDATE_SYSTEM}" == "true" ]]; then
        apt-get -y upgrade >/dev/null || true
    fi

    local pkgs=()
    command -v nft  >/dev/null 2>&1 || pkgs+=("nftables")
    command -v curl >/dev/null 2>&1 || pkgs+=("curl")
    if ((${#pkgs[@]})); then
        echo "[+] Installing: ${pkgs[*]}"
        apt-get install -y "${pkgs[@]}" >/dev/null
    fi

    if ! command -v nft >/dev/null 2>&1; then
        echo -e "${RED}FATAL: nftables not available after install.${NC}"
        exit 1
    fi

    systemctl enable nftables.service >/dev/null 2>&1 || true
    systemctl start  nftables.service >/dev/null 2>&1 || true
    echo -e "${GREEN}System ready. Dependencies OK.${NC}"
}

# --- SSH PORT DETECTION ---
detect_ssh_port() {
    local port=""
    # prefer listening sockets (covers non-default ports)
    port=$(ss -ltn 2>/dev/null | awk '/LISTEN/ && /:([0-9]+)$/ {gsub(/.*:/,"",$4); print $4}' | sort -u |
           while read -r p; do ss -ltnp "sport = :$p" 2>/dev/null | grep -q sshd && echo "$p" && break; done || true)
    if [[ -z "${port:-}" ]]; then
        port=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 || true)
    fi
    [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || port=22
    echo "$port"
}

ensure_config_dir() {
    mkdir -p "$CONFIG_DIR"
    : > /dev/null
    [ -f "$ALLOWED_TCP_PORTS_FILE" ] || touch "$ALLOWED_TCP_PORTS_FILE"
    [ -f "$ALLOWED_UDP_PORTS_FILE" ] || touch "$ALLOWED_UDP_PORTS_FILE"
    [ -f "$BLOCKED_IPS_FILE" ]      || touch "$BLOCKED_IPS_FILE"
}

ensure_ssh_in_config() {
    local ssh_port; ssh_port=$(detect_ssh_port)
    # write SSH port into allowed TCP ports file if not already present
    if ! grep -qx "$ssh_port" "$ALLOWED_TCP_PORTS_FILE"; then
        echo "$ssh_port" >> "$ALLOWED_TCP_PORTS_FILE"
    fi
}

# --- BLOCKLIST ---
update_blocklist() {
    local is_initial_setup=${1:-false}
    echo -e "${YELLOW}Downloading latest blocklist...${NC}"
    local temp_file; temp_file=$(mktemp)
    if curl -fsSL "$BLOCKLIST_URL" -o "$temp_file"; then
        if [ -s "$temp_file" ] && [ "$(wc -l < "$temp_file")" -gt 10 ]; then
            sed -i 's/\r$//' "$temp_file"
            mv "$temp_file" "$BLOCKED_IPS_FILE"
            echo -e "${GREEN}Blocklist updated.${NC}"
            [[ "$is_initial_setup" == false ]] && prompt_to_apply
            return 0
        fi
    fi
    echo -e "${RED}Blocklist download failed or too small. Keeping existing.${NC}"
    rm -f "$temp_file" || true
    return 1
}

create_default_blocked_ips_fallback() {
    cat > "$BLOCKED_IPS_FILE" << 'EOL'
# FALLBACK LIST
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOL
}

# --- INITIAL SETUP ---
initial_setup() {
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
        # No prompts on first run
        add_ports_interactive "TCP" --no-prompt
        echo -e "\n${GREEN}Initial configuration complete.${NC}"
        echo "Select 'Apply Firewall Rules' to activate."
        press_enter_to_continue
    else
        # Keep SSH allowed in case user changed sshd recently
        ensure_ssh_in_config
    fi
}

# --- APPLY RULES ---
apply_rules() {
    local no_pause=false
    [[ "${1:-}" == "--no-pause" ]] && no_pause=true
    [[ "$no_pause" == false ]] && clear
    echo "[+] Building new nftables ruleset..."

    ensure_config_dir

    local ssh_port; ssh_port=$(detect_ssh_port)
    ensure_ssh_in_config

    # Robust to empty files; don't let grep/sort failures abort with pipefail
    local tcp_ports udp_ports
    tcp_ports=$(
      { sort -un "$ALLOWED_TCP_PORTS_FILE" 2>/dev/null | grep -v -x "${ssh_port}" || true; } \
      | tr '\n' ',' | sed 's/,$//'
    )
    udp_ports=$(
      { sort -un "$ALLOWED_UDP_PORTS_FILE" 2>/dev/null || true; } \
      | tr '\n' ',' | sed 's/,$//'
    )

    # Build set elements (safe when empty)
    local blocked_elems=""
    while IFS= read -r raw; do
        local line
        line=$(echo "$raw" | tr -d '\r' | xargs)
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        if [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            blocked_elems+="${line},"
        fi
    done < "$BLOCKED_IPS_FILE"
    blocked_elems=${blocked_elems%,}

    local set_block="
    set blocked_v4 {
        type ipv4_addr
        flags interval
"
    if [[ -n "$blocked_elems" ]]; then
        set_block+="        elements = { ${blocked_elems} }
"
    fi
    set_block+="    }
"

    local ruleset="flush ruleset
table inet firewall-manager {
${set_block}
    chain input {
        type filter hook input priority 0; policy drop;
        ct state { established, related } accept
        iif lo accept
        ct state invalid drop
        ip saddr @blocked_v4 drop
        tcp dport ${ssh_port} accept
"
    if [[ -n "$tcp_ports" ]]; then
        ruleset+="        tcp dport { ${tcp_ports} } accept
"
    fi
    if [[ -n "$udp_ports" ]]; then
        ruleset+="        udp dport { ${udp_ports} } accept
"
    fi
    ruleset+="    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ip saddr @blocked_v4 drop
        ip daddr @blocked_v4 drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr @blocked_v4 drop
    }
}
"

    if echo -e "$ruleset" | nft -f -; then
        echo -e "\n${GREEN}Firewall configuration applied successfully!${NC}"
        echo -e "${YELLOW}Saving rules to /etc/nftables.conf...${NC}"
        nft list ruleset > /etc/nftables.conf
        systemctl restart nftables.service || true
        echo -e "${GREEN}Rules persisted.${NC}"
    else
        echo -e "\n${RED}FATAL: Failed to apply nftables ruleset!${NC}"
        echo "Check for syntax errors or invalid entries in your config files."
    fi

    [[ "$no_pause" == false ]] && press_enter_to_continue
}

# --- MENUS & UTILITIES ---
prompt_to_apply() {
    echo ""
    read -r -p "Apply these changes now to make them live? (y/n): " confirm < /dev/tty
    if [[ "$confirm" =~ ^[yY]$ ]]; then apply_rules --no-pause
    else echo -e "${YELLOW}Changes saved to config but NOT applied.${NC}"
    fi
}

parse_and_process_ports() {
    local action="$1"; local proto_file="$2"; local input_ports="$3"
    local count=0; local ssh_port; ssh_port=$(detect_ssh_port)
    IFS=',' read -ra port_items <<< "$input_ports"
    for item in "${port_items[@]}"; do
        item=$(echo "$item" | xargs)
        if [[ "$item" == *-* ]]; then
            local start_port end_port
            start_port=$(echo "$item" | cut -d'-' -f1)
            end_port=$(echo "$item" | cut -d'-' -f2)
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
    if ((count>0)); then echo -e "\n${GREEN}Configuration updated.${NC}"; prompt_to_apply
    else echo -e "\nNo changes were made."
    fi
}

add_ports_interactive() {
    local proto="$1"; local no_prompt=${2:-""}
    if [[ "$no_prompt" != "--no-prompt" ]]; then clear; echo -e "${YELLOW}--- Add Allowed ${proto} Ports ---${NC}"; fi
    local proto_file; [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
    echo "Current ${proto} ports: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
    if [[ "$no_prompt" != "--no-prompt" ]]; then
        read -r -p "Enter ${proto} port(s) to add (e.g., 80,443 or 1000-2000): " input_ports < /dev/tty
        [[ -n "$input_ports" ]] && parse_and_process_ports "add" "$proto_file" "$input_ports"
    fi
}

remove_ports_interactive() {
    local proto="$1"
    local proto_file; [[ "$proto" == "TCP" ]] && proto_file="$ALLOWED_TCP_PORTS_FILE" || proto_file="$ALLOWED_UDP_PORTS_FILE"
    clear; echo -e "${YELLOW}--- Remove Allowed ${proto} Ports ---${NC}"
    echo "Current ${proto} ports: $(sort -n "$proto_file" 2>/dev/null | paste -s -d, || echo "None")"
    read -r -p "Enter ${proto} port(s) to remove: " input_ports < /dev/tty
    [[ -n "$input_ports" ]] && parse_and_process_ports "remove" "$proto_file" "$input_ports"
}

view_rules() { clear; echo -e "${YELLOW}--- Current Active NFTABLES Ruleset ---${NC}"; nft list ruleset; press_enter_to_continue; }

manage_tcp_ports_menu() {
    while true; do
        clear; echo "--- Manage Allowed TCP Ports ---"
        echo "1) Add TCP Port(s)"; echo "2) Remove TCP Port(s)"; echo "3) Back"
        read -r -p "Choose an option: " choice < /dev/tty
        case $choice in
            1) add_ports_interactive "TCP"; press_enter_to_continue ;;
            2) remove_ports_interactive "TCP"; press_enter_to_continue ;;
            3) break ;;
            *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
        esac
    done
}

manage_udp_ports_menu() {
    while true; do
        clear; echo "--- Manage Allowed UDP Ports ---"
        echo "1) Add UDP Port(s)"; echo "2) Remove UDP Port(s)"; echo "3) Back"
        read -r -p "Choose an option: " choice < /dev/tty
        case $choice in
            1) add_ports_interactive "UDP"; press_enter_to_continue ;;
            2) remove_ports_interactive "UDP"; press_enter_to_continue ;;
            3) break ;;
            *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
        esac
    done
}

manage_ips_menu() {
    echo -e "\n${YELLOW}This feature is still under development for the nftables version.${NC}"
    press_enter_to_continue
}

flush_rules() {
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

uninstall_script() {
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

main_menu() {
    while true; do
        clear
        echo "==============================="
        echo " NFTABLES FIREWALL MANAGER v5.8"
        echo "==============================="
        echo "1) View Current Firewall Rules"
        echo "2) Apply Firewall Rules from Config"
        echo "3) Manage Allowed TCP Ports"
        echo "4) Manage Allowed UDP Ports"
        echo "5) Manage Blocked IPs (WIP)"
        echo "6) Update IP Blocklist from Source"
        echo "7) Flush All Rules & Reset Config"
        echo "8) Uninstall Firewall & Script"
        echo "9) Exit"
        echo "-------------------------------"
        read -r -p "Choose an option: " choice < /dev/tty
        case $choice in
            1) view_rules ;;
            2) apply_rules ;;
            3) manage_tcp_ports_menu ;;
            4) manage_udp_ports_menu ;;
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
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2
    exit 1
fi
check_dependencies
initial_setup
main_menu
