<p align="center">
  <img src="https://github.com/Nima786/nftables-firewall-manager/blob/main/assets/firewall-manager-logo.webp" alt="Firewall Manager Logo" width="150"/>
</p>

<h1 align="center">NFTABLES Firewall Manager</h1>
<p align="center">
  A powerful, menu-driven Bash utility for managing a hardened <code>nftables</code> firewall on Debian/Ubuntu systems.
  <br><br>
  <a href="https://github.com/Nima786/nftables-firewall-manager/actions/workflows/main.yml"><img src="https://github.com/Nima786/nftables-firewall-manager/actions/workflows/main.yml/badge.svg" alt="ShellCheck"></a>
  <img src="https://img.shields.io/badge/version-v3.6-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

* * *

Quick Install
-------------

Run the script directly from GitHub for a one‑time execution. The script guides you through setup.

    curl -fsSL https://raw.githubusercontent.com/Nima786/nftables-firewall-manager/main/firewall-manager.sh | sudo bash
    

This tool manages its own rules in a dedicated `inet firewall-manager` table, without touching Docker/UFW/system tables. It persists its config to `/etc/nftables.d/firewall-manager.nft` and ensures an `include` in `/etc/nftables.conf`.

<br>
<p align="center">
  <img src="https://github.com/Nima786/nftables-firewall-manager/blob/main/assets/firewall-manager.webp" width="600"/>
</p>

* * *

Why This Script (vs. UFW & older frontends)?
--------------------------------------------

*   **Modern engine:** Uses `nftables` (the successor to iptables) for cleaner syntax and better performance.
*   **True default‑deny everywhere:** _input, forward, output_ chains have `policy drop`, giving real egress control (UFW is typically inbound‑only).
*   **Pre‑Docker priority:** Rules are installed at priority `-10` so they evaluate _before_ Docker’s default chains. You stay in control even with containers.
*   **Efficient big blocklists:** Uses kernel _sets_ with `flags interval` and chunked loading; thousands of CIDRs are matched in O(1) set lookups. Way faster than listing individual rules.
*   **Separation of concerns:** Lives in its own table, never clobbers Docker/UFW/system rules.
*   **Smart UX:** Menus for inbound (panel/inbounds) and outbound (system/nodes/APIs) ports, plus automatic SSH detection and brute‑force throttling.

* * *

Features
--------

*   🛡️ **Strict by default:** `input`, `forward`, `output` all default to `drop`.
*   🔐 **SSH safety:** Auto‑detects SSH port and applies a dynamic set to rate‑limit new attempts (anti‑brute‑force).
*   🌐 **Outbound control:** Minimal essentials are allowed by default: `udp` _53_ (DNS), `udp` _123_ (NTP), `tcp` _22_ (SSH), and `tcp` _80,443_ (HTTP/S) with a rate‑limit. Everything else is blocked unless you explicitly allow it via the menu.
*   📦 **Docker‑aware:** Allows bridged interfaces (e.g., `docker0`, `br-*`) in `forward` so containers keep working while your host remains locked down.
*   🚫 **High‑performance blocklist:** Downloads an IPv4 abuse/bogon list, prunes/merges CIDRs, and _loads in chunks_ into a kernel set after the table is created. Fast lookups, low CPU.
*   🧠 **Resilient loading:** If Python/ipaddress pruning isn’t available, it falls back to the raw list; duplicates are de‑duplicated; the set is flushed before reload to avoid errors.
*   🧩 **Non‑destructive:** Only its own table is created/removed. No changes to Docker/UFW/system tables.
*   📝 **Clear logging:** Drops are logged with prefixes (`[NFT DROP in/out/fwd]`) for quick auditing.
*   🧽 **Clean uninstall:** Removes only its table, persisted file, config (optionally the script itself).

* * *

Compatibility & Coexistence
---------------------------

*   **OS:** Ubuntu 20.04/22.04/24.04, Debian 11/12.
*   **IP version:** Rules run in `inet` family. The dynamic blocklist focuses on IPv4 (IPv6 default‑deny still applies unless you open ports).
*   **Docker:** Safe alongside Docker; our table runs at priority `-10` (before Docker’s default rules at `0`), and bridged interfaces are accommodated.
*   **UFW:** Can coexist, but if you want _one_ source of truth, disable UFW: `sudo ufw disable`. This script does _not_ modify UFW automatically.

* * *

Permanent Installation
----------------------

Install once and rerun anytime:

    # Download
    sudo curl -fsSL https://raw.githubusercontent.com/Nima786/nftables-firewall-manager/main/firewall-manager.sh -o /usr/local/bin/firewall-manager
    
    # Make executable
    sudo chmod +x /usr/local/bin/firewall-manager
    
    # Run
    sudo firewall-manager
    

On the first run, dependencies are installed, a config directory is created, and the blocklist is fetched.

* * *

Important Defaults
------------------

*   **Inbound:** Only your detected SSH port is allowed by default. Add panel/inbound ports via the menu.
*   **Outbound:** Defaults allow DNS(53/udp), NTP(123/udp), SSH(22/tcp), HTTP/HTTPS(80/443 tcp, rate‑limited). Add node/API ports via the menu if needed.
*   **Persistence:** Rules are written to `/etc/nftables.d/firewall-manager.nft` and included from `/etc/nftables.conf`.

* * *

Menu Options Explained
----------------------

*   **1) View Current Firewall Rules** — Shows only the `firewall-manager` table (and prints the `blocked_ips` set for visibility).
*   **2) Apply Firewall Rules from Config** — Builds and applies rules from config files; loads the blocklist set in chunks; then persists.
*   **3) Allow TCP Inbound Ports (For Panel/Inbounds)** — Add/remove TCP ports or ranges for _incoming_ traffic.
*   **4) Allow UDP Inbound Ports (For Panel/Inbounds)** — Add/remove UDP ports or ranges for _incoming_ traffic.
*   **5) Manage Blocked IPs** — Add/remove IPv4 addresses/CIDRs in your blocklist file.
*   **6) Update IP Blocklist from Source** — Fetch the latest IPv4 abuse list and save it locally (applies on next “2) Apply”).
*   **7) Allow Outbound Ports (For System/Nodes/APIs)** — Add/remove TCP/UDP _egress_ ports (e.g., node control/API ports).
*   **8) Flush All Rules & Reset Config** — Deletes only the `firewall-manager` table and resets this tool’s config (other nftables tables untouched).
*   **9) Uninstall Firewall & Script** — Removes the table, persisted file, config, and the script itself.
*   **0) Exit**

* * *

Configuration Files
-------------------

All configuration lives under `/etc/firewall_manager_nft/`:

*   `allowed_tcp_ports.conf` — Inbound TCP allowlist
*   `allowed_udp_ports.conf` — Inbound UDP allowlist
*   `allowed_node_tcp_ports.conf` — Outbound TCP allowlist
*   `allowed_node_udp_ports.conf` — Outbound UDP allowlist
*   `blocked_ips.conf` — IPv4 blocklist (downloaded/merged)

* * *

Verification & Troubleshooting
------------------------------

    # View rules managed by this tool
    sudo nft list table inet firewall-manager
    
    # See the full ruleset (including Docker)
    sudo nft list ruleset
    
    # Check SSH brute-force dynamic set
    sudo nft list set inet firewall-manager ssh_brute
    
    # Inspect blocklist set
    sudo nft list set inet firewall-manager blocked_ips | head -n 100
    
    # View drops (input/output/forward)
    journalctl -k | grep "NFT DROP"
    

**Tip:** If you want this tool to be your single firewall authority, consider disabling UFW (`sudo ufw disable`) to avoid policy confusion.

* * *

Emergency Rollback
------------------

Remove only this tool’s table (Docker/UFW/system rules remain):

    sudo nft delete table inet firewall-manager
    

* * *

Performance Notes
-----------------

*   Blocklists are stored in a kernel _set_, not as one rule per IP. Lookups are extremely fast.
*   `flags interval` and pruning merge overlapping CIDRs, minimizing memory and comparisons.
*   Established/related traffic is accepted early, so most packets never hit expensive checks.

* * *

Requirements
------------

*   Ubuntu 20.04+ or Debian 11+
*   `sudo` privileges
*   Internet access (first run + blocklist updates)

* * *

License
-------

MIT

* * *

What’s New in v3.9.5
--------------------

*   Robust, chunked blocklist loading (after table creation) with prune fallback and safe deduplication.
*   Outbound allowlist menu (System/Nodes/APIs) + minimal default egress allows with HTTP/HTTPS rate‑limit.
*   Runs at priority `-10` to evaluate before Docker rules.
*   Removed redundant `daddr` blocklist check from `INPUT` (kept in `FORWARD`/`OUTPUT`), preserving strictness while trimming one lookup.
*   Persists rules _after_ loading the blocklist set for reliable reboots.
