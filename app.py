import ipaddress
import os
import platform
import re
import subprocess

import nmap
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

# In-memory storage for firewall rules
firewall_rules = []

# Nmap arguments per scan type; anything else falls back to a full TCP connect scan
SCAN_ARGS = {
    'tcp': '-sS',      # TCP SYN Scan
    'udp': '-sU',      # UDP Scan
    'version': '-sV',  # Service Version Detection
}
DEFAULT_SCAN_ARGS = '-sT'  # Full TCP Connect Scan
ACTIONS = ('allow', 'deny')
HOSTNAME_RE = re.compile(r'(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?')


# ---------- input validation ----------

def parse_ip(value):
    """Return a normalized single IP address, or None if invalid."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def parse_target(value):
    """Return an IP, CIDR range or hostname to scan, or None if invalid."""
    value = str(value).strip()
    ip = parse_ip(value)
    if ip:
        return ip
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        pass
    # Hostname: dot-separated labels of letters, digits and hyphens (RFC 1123)
    if HOSTNAME_RE.fullmatch(value):
        return value.lower()
    return None


def parse_port(value):
    """Return the port as an int in 1-65535, or None if invalid."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


# ---------- environment ----------

def is_privileged():
    """True when running as root (Linux) or Administrator (Windows)."""
    if platform.system() == 'Windows':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, 'geteuid') and os.geteuid() == 0


def server_info():
    return {'os': platform.system(), 'privileged': is_privileged()}


@app.route('/')
def index():
    return render_template('index.html')


@socketio.on('connect')
def handle_connect():
    # Tell the page what it's running against, and restore the current rules after a reload
    emit('server_info', server_info())
    emit('rules_update', firewall_rules)


# Handle scan request
@socketio.on('start_scan')
def handle_scan(data):
    target = parse_target(data.get('target_ip'))
    if target is None:
        emit('scan_error', {'message': 'Invalid target. Enter an IP address, CIDR range or hostname.'})
        return
    arguments = SCAN_ARGS.get(data.get('scan_type'), DEFAULT_SCAN_ARGS)

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        # e.g. SYN/UDP scans need admin/root privileges
        emit('scan_error', {'message': f'Scan failed: {e}'})
        return

    # Process scan results, keeping Nmap's real port state (open/closed/filtered)
    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                info = nm[host][proto][port]
                scan_results.append({
                    'ip': host,
                    'port': port,
                    'proto': proto,
                    'service': info.get('name', ''),
                    'version': ' '.join(x for x in (info.get('product', ''), info.get('version', '')) if x),
                    'state': info['state'],
                    'status': info['state'],
                })

    # Apply firewall rules and simulate traffic flow
    simulate_traffic(scan_results)

    # Emit scan results to frontend
    if scan_results:
        for result in scan_results:
            emit('scan_update', result)
    else:
        emit('scan_update', {
            'ip': target,
            'port': 'N/A',
            'service': 'N/A',
            'status': 'No open ports found'
        })

    # Emit scan complete event to hide animation
    emit('scan_complete', {'target': target, 'arguments': arguments, 'count': len(scan_results)})


# ---------- real firewall enforcement ----------

def _run(cmd):
    """Run a command without a shell. Returns True if it exited successfully."""
    try:
        return subprocess.run(cmd, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"Error running {cmd[0]}: {e}")
        return False


def firewall_command(ip, port, action):
    """Argument list that applies (deny) or removes (allow) the OS firewall rule.

    ip and port must already be validated. Returns None on unsupported systems.
    """
    system = platform.system()
    if system == 'Windows':
        rule_name = f"Block_{ip}_{port}"
        if action == 'deny':
            return ['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={rule_name}',
                    'dir=in', 'action=block', 'protocol=TCP', f'remoteip={ip}', f'localport={port}']
        return ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
    if system == 'Linux':
        flag = '-A' if action == 'deny' else '-D'
        return ['iptables', flag, 'INPUT', '-p', 'tcp', '--dport', str(port), '-s', ip, '-j', 'DROP']
    return None


def add_real_firewall_rule(ip, port, action):
    """Apply (deny) or remove (allow) a real OS firewall rule.

    Arguments are passed as a list, never through a shell, so input can't be
    interpreted as extra commands. Returns True if the OS firewall was changed.
    """
    cmd = firewall_command(ip, port, action)
    if cmd is None:
        return False
    if cmd[0] == 'iptables' and os.geteuid() != 0:
        # -n: fail instead of waiting for a password prompt when not run as root
        cmd = ['sudo', '-n'] + cmd
    return _run(cmd)


# Handle firewall rule creation
@socketio.on('add_firewall_rule')
def handle_firewall_rule(data):
    rule_ip = parse_ip(data.get('ip'))
    rule_port = parse_port(data.get('port'))
    rule_action = data.get('action')

    if rule_ip is None:
        emit('firewall_error', {'message': 'Invalid IP address.'})
        return
    if rule_port is None:
        emit('firewall_error', {'message': 'Port must be a number from 1 to 65535.'})
        return
    if rule_action not in ACTIONS:
        emit('firewall_error', {'message': 'Action must be allow or deny.'})
        return

    # Deny rules are enforced at the OS level when the app has admin/root rights.
    # Without them the rule still works in the simulation, and the UI says so.
    enforced = add_real_firewall_rule(rule_ip, rule_port, rule_action)
    cmd = firewall_command(rule_ip, rule_port, rule_action)

    rule = {'ip': rule_ip, 'port': rule_port, 'action': rule_action, 'enforced': enforced,
            'command': ' '.join(cmd) if cmd else ''}
    firewall_rules.append(rule)

    # Emit the rule to the frontend for visualization
    emit('firewall_rule_added', rule)
    emit('rules_update', firewall_rules)


@socketio.on('remove_firewall_rule')
def handle_remove_firewall_rule(data):
    try:
        rule_number = int(data.get('rule_number')) - 1  # Convert to 0-based index
    except (TypeError, ValueError):
        rule_number = -1

    if 0 <= rule_number < len(firewall_rules):
        rule = firewall_rules.pop(rule_number)
        command = ''

        # Remove the real firewall rule if one was applied
        if rule['action'] == 'deny' and rule['enforced']:
            add_real_firewall_rule(rule['ip'], rule['port'], 'allow')
            command = ' '.join(firewall_command(rule['ip'], rule['port'], 'allow'))

        emit('firewall_rule_removed', {'rule_number': rule_number + 1, 'rule': rule, 'command': command})
        emit('rules_update', firewall_rules)
    else:
        emit('firewall_error', {'message': 'Invalid rule number'})


# Simulate traffic flow based on firewall rules
def simulate_traffic(scan_results):
    """Mark ports covered by a deny rule as Blocked; others keep their Nmap state."""
    for result in scan_results:
        result['blocked'] = False
        for rule in firewall_rules:
            # First matching rule wins, like most firewalls
            if rule['ip'] == result['ip'] and rule['port'] == result['port']:
                if rule['action'] == 'deny':
                    result['status'] = 'Blocked'
                    result['blocked'] = True
                break


# Start the server
if __name__ == '__main__':
    # Local-only tool: bound to 127.0.0.1 with the debugger off.
    # allow_unsafe_werkzeug lets the built-in dev server start outside a terminal.
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)
