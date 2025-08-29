![ShellCheck](https://github.com/Nima786/iptables-firewall-manager/actions/workflows/main.yml/badge.svg)

## Quick Install
```bash
curl -fsSL https://raw.githubusercontent.com/Nima786/iptables-firewall-manager/main/firewall-manager.sh | sudo bash


# IPTABLES Firewall Manager (v3.4)

A menu-driven Bash utility for managing a hardened `iptables` firewall on Debian/Ubuntu systems.  
It sets sane default policies, allows specific TCP/UDP ports, applies an IP blocklist, and makes rules persistent across reboots.

## Features
- Interactive menus to view/apply rules and manage allowed ports and blocked IPs
- Persists rules via `netfilter-persistent`
- Optional automatic download of an external IPv4 blocklist
- Safe guard: SSH port (default 22/tcp) is always kept open
- Reset & uninstall flows to revert the firewall

## Requirements
- Root privileges (`sudo`)
- Debian/Ubuntu with `iptables-persistent` and `curl` (the script can install them automatically)
- Internet access (only if you want to refresh the remote blocklist)

## Quick start
```bash
sudo bash firewall-manager.sh
```
On first run it creates config files in `/etc/firewall_manager/`, offers to add allowed ports (e.g., `80,443`) and can download an IP blocklist.  
Select **Apply Firewall Rules** to activate.

## Common actions
- **View Current Firewall Rules** – prints the live `iptables` rules
- **Apply Firewall Rules from Config** – re-applies rules defined in the config files
- **Manage Allowed TCP/UDP Ports** – add/remove single ports or ranges
- **Manage Blocked IPs** – add/remove IP/CIDR entries to the local blocklist
- **Update IP Blocklist from Source** – refresh the remote blocklist file
- **Flush & Reset** – opens the firewall and recreates a fresh config
- **Uninstall** – removes config and persists an open ruleset

## Notes
- If you're using a cloud VM, keep the console open while changing firewall rules to avoid lock‑outs.
- You can run the script without file execute bit by invoking `bash firewall-manager.sh` (GitHub Web uploads don’t set the executable permission).

## License
MIT
