# Network Security Scanner with Firewall Rule Simulator

A real-time network security scanner and traffic control simulator built with **Python (Flask)**, **Flask-SocketIO**, and **Nmap**. Built to understand how network scanning and firewall logic actually work under the hood, the same core concepts used in tools like Nmap and pfSense, through a fully interactive, live web interface.

## Overview

This project provides an educational, hands-on sandbox for exploring network-level security concepts. Users can:

- Run live port scans in multiple modes (TCP SYN, UDP, service version detection)
- Create and manage firewall simulation rules (`allow` / `deny`) by IP and port
- Watch traffic get filtered in real time based on the rules applied
- See, visually and interactively, how firewall logic actually shapes what traffic gets through

I built this to go beyond just using scanning tools like Nmap and firewall interfaces like pfSense, and actually understand the mechanics behind them: how a scan differentiates open, closed, and filtered ports, and how firewall rule ordering and matching decide what traffic is allowed through.

**This isn't just a visual simulation.** When run with elevated privileges, adding a "deny" rule executes a real system-level firewall command, `netsh advfirewall` on Windows or `iptables` on Linux, actually blocking the specified IP and port at the OS level, not just in the UI. Removing the rule reverses it the same way. Allow rules are real too: they let traffic through even inside a blocked range, so you can block a whole subnet and still allow one machine.

---

## Installation

### Requirements

- Python 3.11
- `nmap` installed on your system
  - **Linux**: `sudo apt install nmap`
  - **macOS**: `brew install nmap`
  - **Windows**: [Download from nmap.org](https://nmap.org/download.html)
- Administrator (Windows) or root/sudo (Linux) privileges, required for the app to apply real firewall rules rather than just simulate them

### Setup

```bash
pip install -r requirements.txt
```

---

## Features

**Flexible Scanning**
- Scan an IP address, a CIDR range (up to a /22) or a hostname
- TCP SYN scan, TCP connect scan, UDP scan and service version detection
- Scans run in the background: ranges are scanned in batches of 16 hosts with a live progress bar and a **Stop** button
- **Scan diff:** each scan is compared with the last one of the same target and type, flagging new open ports and ports that closed
- **Export** results as CSV or JSON (spreadsheet formula injection is neutralized in CSV)

**Simulated + Real Firewall Enforcement**
- Add allow or deny rules by source IP or CIDR range, single port or port range, TCP or UDP
- When run with admin/root privileges, both rule types are real `iptables` (Linux) or `netsh` (Windows) rules: deny rules block traffic at the OS level and allow rules let it through
- **Allow wins over deny:** allow one address or port inside a blocked range and only that gets through, whatever order the rules were added in. Removing the allow rule puts the full block back
  - On Linux, an allow rule is an `ACCEPT` at the top of the `INPUT` chain, so iptables reaches it before any `DROP`
  - On Windows, a block rule always wins over an allow rule, so the app rewrites the block with the allowed part cut out. Blocking `10.0.0.0/24` while allowing `10.0.0.50` becomes a block on `10.0.0.0-10.0.0.49` and `10.0.0.51-10.0.0.255`, plus a real allow rule for `10.0.0.50`
- The rule list shows which allow rules take priority over part of a deny rule
- Without admin/root privileges, rules still work in the simulation and are labeled "simulated only"
- Remove rules dynamically, real and simulated
- **Auto-expiry:** rules can expire after 15 minutes, 1 hour or 24 hours, and are removed from the OS firewall on time
- **Block log:** every rule added, removed, expired or restored is written to `state/block_log.jsonl`, an audit trail that survives restarts
- **Persistence:** rules are saved to `state/firewall_rules.json` and restored on startup. If an OS rule went missing (for example, Linux clears iptables on reboot), it is re-applied; rules that expired while the app was off are removed
- Visualize rule impact on live scan results: ports keep their real Nmap state (open, closed, filtered) unless a deny rule that no allow rule overrides marks them Blocked

**Operator Console UI**
- WebSocket-driven updates, no manual refresh needed
- Header shows the connection, the OS and whether the app is running with admin/root rights
- Color-coded port states with open / filtered / closed / blocked counts
- One-click **Block** on open ports, **Unblock** on a port with its own rule, and **Allow** on a port blocked by a wider range rule
- Preview of the exact `iptables` or `netsh` command before a rule is added
- Timestamped activity log of scans, rules and errors
- Rules and the block log are restored after a page reload, and the layout adapts to narrow browser windows

---

## How to Use

```bash
python app.py
```

Run it with `sudo` (Linux) or from an Administrator terminal (Windows) to enforce rules at the OS level.

Then open `http://127.0.0.1:5000` in your browser:

1. Enter a target IP address, CIDR range or hostname
2. Pick a scan type and click **Start scan**
3. Press **Block** on an open port, or add a rule by source IP and port
4. Watch the port change to Blocked, and check the activity log for the command that ran
5. Press **Unblock** or the ✕ next to a rule to remove it

---

## Use Cases

- Networking and cybersecurity education
- Visual demonstration of firewall rule behavior
- Hands-on exploration of WebSockets and real-time interaction with Flask

---

## Project Outputs

**Full dashboard: a port blocked by a real iptables rule**
![Dashboard with a blocked port](docs/screenshots/04-port-blocked.png)
Rescanning after the block, port 8080 no longer shows as open, because the OS firewall now drops the scanner's probes too.

**Live scan in progress**
![Scan in progress](docs/screenshots/01-scan-running.png)

**Scan compared with the last one: a new open port flagged**
![Scan results](docs/screenshots/02-scan-results.png)

**Adding a subnet and port-range rule with a 1 hour expiry, with the exact command previewed**
![Adding a firewall rule](docs/screenshots/03-add-rule.png)

**Activity log: scans, new-port warnings and the firewall commands that ran**
![Activity log](docs/screenshots/05-activity-log.png)

---

## Tests

```
pip install pytest
python -m pytest tests
```

- The rule logic is tested for both Linux and Windows against a stand-in firewall that behaves like iptables (first match wins) and like Windows Firewall (a block beats an allow)
- `tests/test_real_firewall.py` changes the real OS firewall, so it only runs with `REAL_FIREWALL=1` as root or Administrator:
  - **Linux:** a real connection is dropped by a deny rule, let through by an allow rule, and dropped again once the allow rule is removed
  - **Windows:** the Windows Firewall rules are read back with `netsh`, checking that the allowed address and port were cut out of the block
- GitHub Actions runs all of them on Linux and Windows on every push

---

## Security

The first version built firewall commands from user input and ran them with `shell=True`, a command injection risk. I found it in a self-review and fixed it:

- IP addresses, ports, rule actions and scan targets are validated before use (Python's `ipaddress` module, port range 1-65535, allow/deny only)
- Firewall commands are passed as argument lists with no shell, so input can't be interpreted as extra commands
- On Linux, `sudo -n` fails cleanly instead of hanging on a password prompt
- The server binds to `127.0.0.1` with Flask's debugger turned off

---

## Known Limitations

- Real firewall rule application currently only supports Windows (`netsh`) and Linux (`iptables`); no macOS support yet.
- SYN and UDP scans require admin/root privileges (an Nmap requirement). TCP connect scans work without them.
- A scan can only be stopped between batches, so a single host scan runs until Nmap finishes.
- Blocking an address range that includes your own machine also hides those ports from your own scans, since the OS firewall drops the scanner's probes too. The app warns you before you add such a rule and keeps the warning on the rule.
- Rules created with a different OS user or outside the app are not tracked. The app only manages rules it created.
- On Windows, allowed traffic is cut out of the block rules this app created. Block rules made outside the app still win over its allow rules.
- Windows Firewall doesn't filter traffic a computer sends to itself, so on Windows, rules only affect traffic from other machines.

---

## License

Released under the [MIT License](LICENSE). Intended for educational and personal use. Feel free to modify and extend it.
