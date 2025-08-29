#!/bin/bash

# =================================================================
#        Interactive NFTABLES Firewall Manager - v4.0
# =================================================================
# A menu-driven utility to manage a modern nftables firewall.
# v4.0: Complete rewrite from iptables to nftables.
#       - Unified IPv4/IPv6 rule management.
#       - Automatic SSH port detection.

# --- CONFIGURATION ---
CONFIG_DIR="/etc/firewall_manager_nft"
ALLOWED_PORTS_FILE="$CONFIG_DIR/allowed_ports.conf"
BLOCKED_IPS_FILE="$CONFIG_DIR/blocked_ips.conf"
BLOCKLIST_URL="https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4"

# --- COLORS ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- HELPER FUNCTIONS ---
function press_enter_to_continue() {
    echo ""
    read -r -p "Press Enter to return..." < /dev/tty
}

# --- DEPENDENCY AND SETUP FUNCTIONS ---
function check_dependencies() {
    echo "[+] Checking for required dependencies..."
    if ! command -v nft &> /dev/null; then
        echo -e "${YELLOW}Dependency 'nftables' not found. Attempting to install...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y nftables curl
        if ! command -v nft &> /dev/null; then echo -e "${RED}FATAL: Failed to install 'nftables'.${NC}"; exit 1; fi
        systemctl enable nftables.service
        systemctl start nftables.service
        echo -e "${GREEN}'nftables' installed and enabled successfully.${NC}"
    fi
    # Other dependencies can be added here
}

function detect_ssh_port() {
    # Try to find the listening port from ss, fallback to config, then to default 22
    local port
    port=$(ss -ltn 'sport = :*' 2>/dev/null | grep -oP 'sshd.*:(\K[0-9]+)' | head -n 1)
    if [[ -z "$port" ]]; then
        port=$(grep -i '^Port' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    fi
    echo "${port:-22}" # Default to 22 if still not found
}

function update_blocklist() {
    local is_initial_setup=${1:-false}
    echo -e "${YELLOW}Attempting to download latest blocklist from source...${NC}"; local temp_file=$(mktemp)
    if curl -sL "$BLOCKLIST_URL" -o "$temp_file"; then
        if [ -s "$temp_file" ] && [ $(wc -l < "$temp_file") -gt 10 ]; then
            sed -i 's/\r$//' "$temp_file"; mv "$temp_file" "$BLOCKED_IPS_FILE"
            echo -e "${GREEN}Blocklist successfully downloaded and updated.${NC}"
            if [[ "$is_initial_setup" == false ]]; then prompt_to_apply; fi
        else echo -e "${RED}Error: Downloaded file was empty or too small. Aborting update.${NC}"; rm -f "$temp_file"; return 1; fi
    else echo -e "${RED}Error: Failed to download blocklist.${NC}"; rm -f "$temp_file"; return 1; fi
    return 0
}

function create_default_blocked_ips_fallback() {
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

function initial_setup() {
    if [ ! -d "$CONFIG_DIR" ]; then
        echo -e "${YELLOW}First time setup: Creating configuration...${NC}"; mkdir -p "$CONFIG_DIR"
        local ssh_port=$(detect_ssh_port)
        echo "${ssh_port}/tcp" > "$ALLOWED_PORTS_FILE"
        echo -e "${GREEN}Detected and allowed SSH on port ${ssh_port}/tcp.${NC}"
        if ! update_blocklist true; then echo -e "${YELLOW}Using a fallback local blocklist...${NC}"; create_default_blocked_ips_fallback; fi
        add_ports_interactive --no-prompt
        echo -e "\n${GREEN}Initial configuration complete.${NC}"; echo "Please select 'Apply Firewall Rules' to activate your setup."; press_enter_to_continue
    fi
}

function apply_rules() {
    local no_pause=false; if [[ "$1" == "--no-pause" ]]; then no_pause=true; fi
    if [[ "$no_pause" == false ]]; then clear; fi
    
    echo "[+] Building new nftables ruleset..."

    # Prepare port and IP lists
    local tcp_ports=$(grep '/tcp$' "$ALLOWED_PORTS_FILE" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    local udp_ports=$(grep '/udp$' "$ALLOWED_PORTS_FILE" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    local blocked_ips=$(grep -v '^#' "$BLOCKED_IPS_FILE" | grep . | tr '\n' ',' | sed 's/,$//')
    
    # Use a here-document to atomically apply the entire ruleset
    nft -f - <<- EOF
        flush ruleset

        table inet firewall-manager {
            set abuse_defender_ipv4 {
                type ipv4_addr
                flags interval
                elements = { ${blocked_ips} }
            }

            chain input {
                type filter hook input priority 0; policy drop;
                
                # Allow established/related connections
                ct state { established, related } accept
                
                # Allow loopback traffic
                iif lo accept
                
                # Drop invalid packets
                ct state invalid drop
                
                # Allow configured TCP ports
                tcp dport { ${tcp_ports} } accept

                # Allow configured UDP ports
                udp dport { ${udp_ports} } accept
            }
            
            chain forward {
                type filter hook forward priority 0; policy drop;

                # Block traffic to malicious destinations
                ip daddr @abuse_defender_ipv4 drop
            }

            chain output {
                type filter hook output priority 0; policy accept;

                # Block traffic to malicious destinations
                ip daddr @abuse_defender_ipv4 drop
            }
        }
EOF

    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}Firewall configuration applied successfully!${NC}"
        echo -e "${YELLOW}Saving rules to make them persistent...${NC}"
        nft list ruleset > /etc/nftables.conf
        systemctl restart nftables.service
        echo -e "${GREEN}Rules have been made persistent.${NC}"
    else
        echo -e "\n${RED}FATAL: Failed to apply nftables ruleset. Firewall may be in an open state!${NC}"
        echo "Check for syntax errors or invalid entries in your config files."
    fi

    if [[ "$no_pause" == false ]]; then press_enter_to_continue; fi
}

function view_rules() {
    clear; echo -e "${YELLOW}--- Current Active NFTABLES Ruleset ---${NC}"
    nft list ruleset
    press_enter_to_continue
}

# --- All management functions (add/remove ports/ips) need to be updated for the new format ---
function add_ports_interactive() {
    # This is a placeholder for the new port management logic.
    # The old logic is removed to avoid confusion.
    # For now, please edit /etc/firewall_manager_nft/allowed_ports.conf manually.
    echo "Port management functions need to be updated for the new nftables version."
    echo "For now, please manually edit the file: ${ALLOWED_PORTS_FILE}"
    press_enter_to_continue
}

# --- MAIN MENU (Simplified for v4.0 Alpha) ---
function main_menu() {
    while true; do
        clear; echo "==============================="; echo " NFTABLES FIREWALL MANAGER v4.0"; echo "==============================="
        echo "1) View Current Firewall Rules"
        echo "2) Apply Firewall Rules from Config"
        echo "3) Edit Allowed Ports (manual edit)"
        echo "4) Update IP Blocklist from Source"
        echo "9) Exit"
        echo "-------------------------------"; read -r -p "Choose an option: " choice < /dev/tty
        case $choice in
            1) view_rules ;;
            2) apply_rules ;;
            3) nano "$ALLOWED_PORTS_FILE";;
            4) update_blocklist; press_enter_to_continue ;;
            9) exit 0 ;;
            *) echo -e "${RED}Invalid option.${NC}" && sleep 1 ;;
        esac
    done
}


# --- SCRIPT START ---
if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2; exit 1; fi
# check_dependencies # Commented out during development
initial_setup
main_menu
