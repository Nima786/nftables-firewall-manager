<p align="center">
  <img src="https://github.com/Nima786/nftables-firewall-manager/blob/main/assets/firewall-manager-logo.webp" alt="Firewall Manager Logo" width="150"/>
</p>
<h1 align="center">NFTABLES Firewall Manager</h1>
<p align="center">
  A powerful, menu-driven Bash utility for managing a hardened <code>nftables</code> firewall on Debian/Ubuntu systems.
  <br />
  <br />
  <a href="https://github.com/Nima786/nftables-firewall-manager/actions/workflows/main.yml"><img src="https://github.com/Nima786/nftables-firewall-manager/actions/workflows/main.yml/badge.svg" alt="ShellCheck"></a>
  <img src="https://img.shields.io/badge/version-v3.5-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

- - -

## Quick Install

Run the script directly from GitHub for a one-time execution. The script will guide you through the initial setup.

```bash
curl -fsSL https://raw.githubusercontent.com/Nima786/nftables-firewall-manager/main/firewall-manager.sh | sudo bash
```

- - -

This script transforms complex `nftables` management into a simple, interactive workflow. It uses modern, high-performance features and is built to be a "good neighbor" on your system, managing its own rules without interfering with other services like Docker or UFW.

<p align="center">
  <img src="https://github.com/Nima786/nftables-firewall-manager/blob/main/assets/firewall-manager.webp" width="600"/>
</p>

## Why Use This Script?

Managing firewalls can be complex, especially on servers running Docker, which often manipulates firewall rules and bypasses simpler tools. This script solves these problems by providing:

*   **A Modern Approach:** Uses `nftables`, the successor to `iptables`, for better performance and syntax.
*   **Safe Coexistence:** Manages its rules in a dedicated `firewall-manager` table, never wiping rules created by Docker or other system services.
*   **High Performance:** Uses `nftables` sets for blocklists, allowing it to handle tens of thousands of IPs with virtually no performance impact.
*   **Simplicity:** An interactive menu that abstracts away complex `nftables` syntax.

- - -

## Features

*   🛡️ **Hardened by Default**: The `input` chain uses a `drop` policy, denying all incoming traffic by default.
*   🔐 **SSH Brute-Force Protection**: Automatically rate-limits new SSH connection attempts to block automated attacks.
*   🚀 **High-Performance IP Blocking**: Uses `nftables` sets for instant lookups against large IP blocklists.
*   🐍 **Intelligent Blocklist Pruning**: An embedded Python helper automatically de-duplicates and merges overlapping IP ranges for maximum efficiency.
*   ✍️ **Firewall Logging**: Logs dropped packets to the system journal for visibility into scans and attacks.
*   🧩 **Safe Docker Coexistence**: Manages its own firewall table surgically, never interfering with tables created by Docker.
*   🌐 **Dynamic Blocklist**: Fetches and applies an updated IPv4 abuse list from an online source.
*   ⚙️ **Multi-Port & Ranges**: Easily add or remove ports, like `80,443` or `1000-2000`.
*   📦 **Auto-Dependencies**: Installs `nftables`, `curl`, and `python3` on the first run if they are missing.
*   🧽 **Clean Uninstall**: Surgically removes only its own rules, files, and configuration, leaving the rest of the system untouched.

- - -

## Compatibility & Docker Coexistence

*   **OS:** Ubuntu 20.04/22.04/24.04, Debian 11/12
*   **IP Version:** The firewall uses the `inet` family to handle both IPv4 and IPv6 traffic. The dynamic blocklist and rate-limiting features in this script are focused on IPv4.
*   **Docker:** This script is designed to work safely alongside Docker. Instead of using the old `DOCKER-USER` chain, it creates its own dedicated `firewall-manager` table and never interferes with the rules Docker creates. It correctly allows forwarded traffic from Docker's bridged networks.

- - -

## Permanent Installation

This method downloads the script and places it in your system's path, allowing you to run it again later just by typing its name. This is the recommended approach for ongoing management.

```bash
# Download the script
sudo curl -fsSL https://raw.githubusercontent.com/Nima786/nftables-firewall-manager/main/firewall-manager.sh -o /usr/local/bin/firewall-manager

# Make it executable
sudo chmod +x /usr/local/bin/firewall-manager

# Run the script
sudo firewall-manager
```

On the first run, the script will install dependencies, create its configuration directory, and download the blocklist.

- - -

## Menu Options Explained

*   **1) `View Current Firewall Rules`**: Shows only the rules in the `firewall-manager` table.
*   **2) `Apply Firewall Rules from Config`**: Builds and applies the rules from your configuration files.
*   **3) `Manage Allowed TCP Ports`**: Add/remove TCP ports or ranges.
*   **4) `Manage Allowed UDP Ports`**: Add/remove UDP ports or ranges.
*   **5) `Manage Blocked IPs`**: Add/remove IPv4 addresses or CIDR ranges from your blocklist.
*   **6) `Update IP Blocklist from Source`**: Fetches the latest abuse list from the configured URL.
*   **7) `Flush All Rules & Reset Config`**: Surgically deletes the `firewall-manager` table and resets the script's configuration.
*   **8) `Uninstall Firewall & Script`**: Performs a clean removal of the `firewall-manager` table, all configuration, and the script itself.
*   **9) `Exit`**: Exits the script.

- - -

## Verification and Troubleshooting

Here are the correct commands to check that your firewall is working as intended.

```bash
# View the rules managed by this script
sudo nft list table inet firewall-manager

# See the full system ruleset, including Docker's tables
sudo nft list ruleset

# Check the contents of the dynamic SSH rate-limiting set
sudo nft list set inet firewall-manager ssh_brute

# View the log of dropped packets
journalctl -k | grep "NFTABLES DROP"
```

- - -

## Emergency Rollback

If you ever need to quickly disable the rules applied by this script without affecting other system rules, run this command:

```bash
sudo nft delete table inet firewall-manager
```

- - -

## Requirements

*   An OS based on Debian/Ubuntu (e.g., Ubuntu 20.04+, Debian 11+).
*   Root privileges (`sudo`) to run.
*   Internet access for the initial download and for updating the blocklist.

## License

This project is licensed under the MIT License.
