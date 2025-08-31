<p align="center">
  <img src="https://github.com/Nima786/iptables-firewall-manager/blob/main/assets/firewall-manager-logo.webp" alt="Firewall Manager Logo" width="150"/>
</p>
<h1 align="center">NFTABLES Firewall Manager</h1>
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

This script turns complex firewall management into a simple, interactive workflow. It’s robust, safe, and **Docker-aware** so container traffic is filtered correctly instead of bypassing your rules (a common issue with UFW).


<p align="center">
  <img src="https://github.com/Nima786/iptables-firewall-manager/blob/main/assets/firewall-manager.webp" width="600"/>
</p>

## Why Use This Script?

Managing iptables can be complex, especially on servers running Docker, which often bypasses traditional firewall tools like UFW. This script solves these problems by providing:
- A single, reliable tool to manage all firewall rules.
- Clean menu that abstracts away iptables syntax.
- **Proper Docker integration** via `DOCKER-USER`.
- Safe, consistent, and repeatable hardening.

## Features

- 🛡️ **Hardened by default** – sets `INPUT` and `FORWARD` to **DROP**.
- 🔐 **Lockout protection** – SSH is safeguarded from removal.
- 🗂️ **Config-driven** – simple text files in `/etc/firewall_manager/`.
- 🧩 **Docker-aware** – filters container traffic without breaking NAT.
- 🌐 **Dynamic blocklist** – fetch and apply an IPv4 abuse list.
- ⚙️ **Multi-port & ranges** – e.g. `80,443` or `1000-2000`.
- 🧑‍💻 **Interactive menus** – view/apply rules, manage TCP/UDP ports & IP blocklist.
- 📦 **Auto-deps** – installs `iptables-persistent`, `curl` if missing.
- 🧽 **Clean uninstall** – flush rules, reset, and remove config/script.

## Security model at a glance
- Default policy: **DROP** for `INPUT` and `FORWARD`, **ACCEPT** for `OUTPUT`.
- Allow **ESTABLISHED**,**RELATED** and loopback.
- `SSH` is always allowed and protected from accidental removal.
- Optional IP blocklist enforced persistently (and in `DOCKER-USER` if present).

## Compatibility
- **OS**: Ubuntu 20.04/22.04/24.04, Debian 11/12
- **Docker**: Supported (rules injected via `DOCKER-USER` when available)
- **IP version**: IPv4 (`iptables`). If your host has public IPv6, manage `ip6tables` separately or disable IPv6 to avoid exposure.

## How Docker is handled (1-liner)
- If `DOCKER-USER` exists, the script inserts its block/allow logic **there first**, so containers are filtered before Docker’s own rules would allow traffic.
  
## Getting Started
The **Quick Install** command is the fastest path. On first run, the script will:
1.  Check for and install missing dependencies.
2.  Create `/etc/firewall_manager/`.
3.  Download the latest IP blocklist (with fallback).
4.  Launch an interactive setup to add your initial **TCP** ports.

After initial setup, select **“2) Apply Firewall Rules from Config”** to activate the secure ruleset.

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

- **1) `View Current Firewall Rules`**: shows live iptables rules.
- **2) `Apply Firewall Rules from Config`**: rebuild & persist from your config files.
- **3) `Manage Allowed TCP Ports`**: add/remove single ports or ranges.
- **4) `Manage Allowed UDP Ports`**: add/remove single ports or ranges.
- **5) `Manage Blocked IPs`**: add/remove IPv4/CIDR entries.
- **6) `Update IP Blocklist from Souce`**: fetch the latest abuse list.
- **7) `Flush All Rules & Reset Config`**: open firewall and re-run initial setup.
- **8) `Uninstall Firewall & Script`**: flush rules, persist open policy, remove config/script.
- **9) `Exit`**: Exits the script.

## Configuration files
All settings live in human-readable files:
-  `/etc/firewall_manager/allowed_tcp_ports.conf `
-  `/etc/firewall_manager/allowed_udp_ports.conf `
-  `/etc/firewall_manager/blocked_ips.conf `
  
 ## Verify it’s working
```bash
sudo iptables -L -n -v --line-numbers          # inspect live rules
sudo iptables -S | less                         # raw rule syntax
sudo netfilter-persistent save                  # confirm persistence
````
 ## Quick rollback (emergency open policy)
```bash
sudo iptables -F; sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo netfilter-persistent save
````

## Requirements
- An OS based on Debian/Ubuntu.
- Root privileges (`sudo`) to run.
- Internet access for the initial download and for updating the blocklist.

## License
This project is licensed under the MIT License.
