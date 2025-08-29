<p align="center">
  <img src="https://github.com/Nima786/iptables-firewall-manager/blob/main/assets/firewall-manager-logo.webp" alt="Firewall Manager Logo" width="150"/>
</p>
<h1 align="center">IPTABLES Firewall Manager</h1>
<p align="center">
  A powerful, menu-driven Bash utility for managing a hardened <code>iptables</code> firewall on Debian/Ubuntu systems.
  <br />
  <br />
  <a href="https://github.com/Nima786/iptables-firewall-manager/actions/workflows/main.yml"><img src="https://github.com/Nima786/iptables-firewall-manager/actions/workflows/main.yml/badge.svg" alt="ShellCheck"></a>
  <img src="https://img.shields.io/badge/version-v3.5-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

---

## Quick Install

 ```bash
curl -fsSL https://raw.githubusercontent.com/Nima786/iptables-firewall-manager/main/firewall-manager.sh | sudo bash
 ````

This script transforms complex iptables management into a simple, interactive process. It's designed to be robust, user-friendly, and safe, with special considerations for modern environments using Docker.

<p align="center">
  <img src="https://github.com/Nima786/iptables-firewall-manager/blob/main/assets/firewall-manager.png" width="600"/>
</p>

## Why Use This Script?

Managing iptables can be complex, especially on servers running Docker, which often bypasses traditional firewall tools like UFW. This script solves these problems by providing:
- A single, reliable tool to manage all firewall rules.
- A user-friendly menu that abstracts away complex iptables syntax.
- **Proper integration with Docker**, ensuring container traffic is filtered correctly.
- A safe, consistent, and repeatable way to secure your servers.

## Features

- 🛡️ **Hardened Security by Default:** Sets default policies to DROP all incoming and forwarded traffic.
- 🗂️ **Configuration-Driven:** Your firewall rules (ports, IPs) are stored in simple text files in /etc/firewall_manager/, not in the script itself.
- 🐳 **Docker-Aware:** Intelligently detects if Docker is running and applies rules to the correct chains to ensure container traffic is properly filtered.
- 🌐 **Dynamic IP Blocklist:** Includes a menu option to download and apply updated IP blocklists from a remote source.
- 🧑‍💻 **Interactive Menus:** Easily view rules, manage allowed TCP/UDP ports, and manage the IP blocklist.
- ⚙️ **Multi-Port & Range Support:** Add or remove multiple ports (80,443) or entire ranges (1000-2000) in a single step.
- 🚑 **Lockout Protection:** The SSH port (22/tcp) is hardcoded as a safety measure to prevent you from accidentally locking yourself out.
- 📦 **Automatic Dependency Installation:** Checks for required packages (iptables-persistent, curl) and installs them if they are missing.
- 🗑️ **Clean Uninstall:** A built-in function to safely flush all rules, reset the firewall, and remove the script and its configurations.

## Getting Started

The **Quick Install** command above is the fastest way to get started. On its first run, the script will:
1.  Check for and install missing dependencies.
2.  Create the configuration directory at /etc/firewall_manager/.
3.  Attempt to download the latest IP blocklist.
4.  Launch an **interactive setup** to ask you for the initial list of TCP ports you want to allow.

After the initial setup, you **must select "2) Apply Firewall Rules from Config"** from the main menu to activate your new secure firewall.

### Permanent Installation (Recommended)
The Quick Install method does not save the script file. For permanent installation, so you can run the manager again later by just typing its name, use this method:

 ```bash
# Download the script and place it in your system's path
sudo curl -fsSL https://raw.githubusercontent.com/Nima786/iptables-firewall-manager/main/firewall-manager.sh -o /usr/local/bin/firewall-manager

# Make it executable
sudo chmod +x /usr/local/bin/firewall-manager

# Run the script
sudo firewall-manager
 ````

## Menu Options Explained

- **1) `View Current Firewall Rules`**: Displays the live iptables rules.
- **2) `Apply Firewall Rules from Config`**: Rebuilds and saves the firewall based on your saved configuration files.
- **3) `Manage Allowed TCP Ports`**: Opens a sub-menu to add or remove TCP ports/ranges.
- **4) `Manage Allowed UDP Ports`**: Opens a sub-menu to add or remove UDP ports/ranges.
- **5) `Manage Blocked IPs`**: Opens a sub-menu to add or remove IPs/CIDRs from your blocklist.
- **6) `Update IP Blocklist from Souce`**: Downloads the latest version of the IP blocklist.
- **7) `Flush All Rules & Reset Config`**: Opens the firewall and guides you through the initial setup process again.
- **8) `Uninstall Firewall & Script`**: Safely removes all firewall rules, configurations, and the script itself.
- **9) `Exit`**: Exits the script.

## Configuration
The script's settings are stored in human-readable text files:
-  `/etc/firewall_manager/allowed_tcp_ports.conf `
-  `/etc/firewall_manager/allowed_udp_ports.conf `
-  `/etc/firewall_manager/blocked_ips.conf `

## Requirements
- An OS based on Debian/Ubuntu.
- Root privileges (sudo) to run.
- Internet access for the initial download and for updating the blocklist.

## License
This project is licensed under the MIT License.
