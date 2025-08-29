![ShellCheck](https://github.com/Nima786/iptables-firewall-manager/actions/workflows/main.yml/badge.svg)

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/Nima786/iptables-firewall-manager/main/firewall-manager.sh | sudo bash

IPTABLES Firewall Manager (v3.4)

A menu-driven Bash utility for managing a hardened iptables firewall on Debian/Ubuntu systems.
It sets sane default policies, allows specific TCP/UDP ports, applies an IP blocklist, and makes rules persistent across reboots.

✨ Features

Interactive menus to view/apply rules and manage allowed ports and blocked IPs

Persists rules via netfilter-persistent

Optional automatic download of an external IPv4 blocklist

Safe guard: SSH port (default 22/tcp) is always kept open

Reset & uninstall flows to revert the firewall

🛠 Requirements

Root privileges (sudo)

Debian/Ubuntu with iptables-persistent and curl (the script can install them automatically)

Internet access (only if you want to refresh the remote blocklist)

🚀 Quick start
sudo bash firewall-manager.sh


On first run it creates config files in /etc/firewall_manager/, offers to add allowed ports (e.g., 80,443), and can fetch a blocklist.
Select Apply Firewall Rules to activate.

📸 Demo (optional)

Add a screenshot of the interactive menu here

🤝 Contributing

Pull requests are welcome! Please run shellcheck locally before submitting.
