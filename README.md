![ShellCheck](https://github.com/Nima786/iptables-firewall-manager/actions/workflows/main.yml/badge.svg)

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/Nima786/iptables-firewall-manager/main/firewall-manager.sh | sudo bash
```

IPTABLES Firewall Manager (v3.4)

A menu-driven Bash utility for managing a hardened iptables firewall on Debian/Ubuntu systems.
It sets sane default policies, allows specific TCP/UDP ports, applies an IP blocklist, and makes rules persistent across reboots.

✨ Features

Interactive menus to view/apply rules and manage allowed ports and blocked IPs

Persists rules via netfilter-persistent

Optional automatic download of an external IPv4 blocklist

Safety guard: SSH (default 22/tcp) is always kept open

Reset & uninstall flows to revert the firewall

🛠 Requirements

Root privileges (sudo)

Debian/Ubuntu with iptables-persistent and curl

(If missing, the script offers to install them automatically.)

Internet access (only if you want to refresh the remote blocklist)

🚀 Quick start (after download)
sudo bash firewall-manager.sh


On first run it creates config files in /etc/firewall_manager/, lets you add allowed ports (e.g., 80,443), and can fetch a blocklist.
Select Apply Firewall Rules to activate.

📓 Notes

If you’re on a cloud VM, keep your console open while changing rules to avoid lockouts.

You can run without execute bit via bash firewall-manager.sh.

🤝 Contributing

Pull requests are welcome! The repo runs ShellCheck on every PR. Please lint locally if possible.

📄 License

MIT © Nima Norouzi

