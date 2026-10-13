import ipaddress
import json
import os
import platform
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from pathlib import Path

import nmap
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

# Saved state lives next to the app, so rules and history survive a restart
STATE_DIR = Path(__file__).resolve().parent / 'state'
RULES_FILE = STATE_DIR / 'firewall_rules.json'
AUDIT_FILE = STATE_DIR / 'block_log.jsonl'
HISTORY_FILE = STATE_DIR / 'scan_history.json'

# Nmap arguments per scan type; anything else falls back to a full TCP connect scan
SCAN_ARGS = {
    'tcp': '-sS',      # TCP SYN Scan
    'udp': '-sU',      # UDP Scan
    'version': '-sV',  # Service Version Detection
}
DEFAULT_SCAN_ARGS = '-sT'  # Full TCP Connect Scan
ACTIONS = ('allow', 'deny')
PROTOCOLS = ('tcp', 'udp')
MAX_SCAN_HOSTS = 1024          # largest range a single scan accepts (a /22)
SCAN_CHUNK = 16                # hosts per Nmap run, so ranges report progress as they go
MAX_RULE_SECONDS = 7 * 24 * 3600
HOSTNAME_RE = re.compile(r'(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?')

# Shared state, touched by socket handlers and the expiry thread
lock = threading.RLock()
firewall_rules = []
recent_audit = deque(maxlen=50)
active_scans = {}  # socket id -> {'cancel': bool}


# ---------- input validation ----------

def parse_ip(value):
    """Return a normalized single IP address, or None if invalid."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def parse_source(value):
    """Return a single IP or a CIDR range for a firewall rule, or None if invalid."""
    ip = parse_ip(value)
    if ip:
        return ip
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    return str(net.network_address) if net.num_addresses == 1 else str(net)


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


def parse_ports(value):
    """Return (low, high) for '22' or '8000-8100', or None if invalid."""
    text = str(value).strip()
    if '-' in text:
        low, _, high = text.partition('-')
        low, high = parse_port(low), parse_port(high)
        if low is None or high is None or low > high:
            return None
        return low, high
    port = parse_port(text)
    return (port, port) if port else None


def parse_duration(value):
    """Return (ok, seconds) where seconds is None for a rule that never expires."""
    if value in (None, '', 0, '0'):
        return True, None
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return False, None
    return (True, seconds) if 1 <= seconds <= MAX_RULE_SECONDS else (False, None)


# ---------- environment and saved state ----------

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
    return {'os': platform.system(), 'privileged': is_privileged(), 'max_scan_hosts': MAX_SCAN_HOSTS}


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default


def save_json(path, data):
    """Write atomically, so a crash never leaves a half-written file."""
    try:
        STATE_DIR.mkdir(exist_ok=True)
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(data, indent=2), encoding='utf-8')
        os.replace(tmp, path)
    except OSError as e:
        print(f"Could not save {path.name}: {e}")


def save_rules():
    save_json(RULES_FILE, firewall_rules)


def rule_label(rule):
    return f"{rule['action']} {rule['ip']} -> {rule['port']}/{rule['proto']}"


def audit(event, rule, level='ok', note=''):
    """Record a rule event in the block log and send it to every open page."""
    command = rule.get('last_command', '')
    msg = f"Rule {event}: {command}" if command else f"Rule {event}: {rule_label(rule)} (simulation)"
    if note:
        msg += f" ({note})"
    entry = {'time': time.time(), 'event': event, 'level': level, 'msg': msg,
             'rule': {k: rule.get(k) for k in ('id', 'ip', 'port', 'proto', 'action', 'enforced', 'expires_at')}}
    with lock:
        recent_audit.append(entry)
        try:
            STATE_DIR.mkdir(exist_ok=True)
            with AUDIT_FILE.open('a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except OSError as e:
            print(f"Could not write block log: {e}")
    socketio.emit('audit', entry)


def broadcast_rules():
    with lock:
        rules = list(firewall_rules)
    socketio.emit('rules_update', rules)


# ---------- real firewall enforcement ----------

def _run(cmd):
    """Run a command without a shell. Returns True if it exited successfully."""
    if cmd[0] == 'iptables' and os.geteuid() != 0:
        # -n: fail instead of waiting for a password prompt when not run as root
        cmd = ['sudo', '-n'] + cmd
    try:
        return subprocess.run(cmd, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"Error running {cmd[0]}: {e}")
        return False


def firewall_command(op, ip, low, high, proto):
    """Argument list to add, delete or check the OS rule that drops this traffic.

    op is 'add', 'delete' or 'check'. ip/ports/proto must already be validated.
    Returns None on systems without a supported firewall.
    """
    system = platform.system()
    if system == 'Windows':
        ports = str(low) if low == high else f'{low}-{high}'
        name = f"name=Block_{ip.replace('/', '_')}_{ports}_{proto}"
        if op == 'add':
            return ['netsh', 'advfirewall', 'firewall', 'add', 'rule', name, 'dir=in', 'action=block',
                    f'protocol={proto.upper()}', f'remoteip={ip}', f'localport={ports}']
        if op == 'delete':
            return ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', name]
        return ['netsh', 'advfirewall', 'firewall', 'show', 'rule', name]
    if system == 'Linux':
        flag = {'add': '-A', 'delete': '-D', 'check': '-C'}[op]
        ports = str(low) if low == high else f'{low}:{high}'
        return ['iptables', flag, 'INPUT', '-p', proto, '--dport', ports, '-s', ip, '-j', 'DROP']
    return None


def apply_os_rule(op, rule):
    """Run add/delete/check for a rule. Returns (succeeded, command text)."""
    cmd = firewall_command(op, rule['ip'], rule['port_lo'], rule['port_hi'], rule['proto'])
    if cmd is None:
        return False, ''
    return _run(cmd), ' '.join(cmd)


def add_real_firewall_rule(ip, port, action, proto='tcp'):
    """Apply (deny) or remove (allow) a real OS firewall rule. Returns True if the OS firewall changed."""
    rule = {'ip': ip, 'port_lo': port, 'port_hi': port, 'proto': proto}
    return apply_os_rule('add' if action == 'deny' else 'delete', rule)[0]


def rule_covers(rule, ip, port, proto):
    """True if the rule's source, port range and protocol all match this traffic."""
    if rule.get('proto', 'tcp') != proto or not rule['port_lo'] <= port <= rule['port_hi']:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(rule['ip'], strict=False)
    except ValueError:
        return False


def remove_rule(rule, event, note=''):
    """Take a rule out of the list and the OS firewall, then log it. Caller holds the lock."""
    firewall_rules.remove(rule)
    if rule['action'] == 'deny' and rule['enforced']:
        _, rule['last_command'] = apply_os_rule('delete', rule)
    else:
        rule['last_command'] = ''
    save_rules()
    audit(event, rule, 'warn' if event == 'expired' else 'ok', note)


def expire_due_rules():
    now = time.time()
    with lock:
        due = [r for r in firewall_rules if r.get('expires_at') and r['expires_at'] <= now]
        for rule in due:
            remove_rule(rule, 'expired')
    if due:
        broadcast_rules()


def expiry_loop():
    while True:
        socketio.sleep(2)
        try:
            expire_due_rules()
        except Exception as e:  # keep the loop alive no matter what
            print(f"Expiry check failed: {e}")


def restore_rules():
    """Load saved rules at startup and bring the OS firewall back in line with them."""
    now = time.time()
    privileged = is_privileged()
    for rule in load_json(RULES_FILE, []):
        rule.setdefault('proto', 'tcp')
        if rule.get('expires_at') and rule['expires_at'] <= now:
            if rule['action'] == 'deny' and rule.get('enforced'):
                _, rule['last_command'] = apply_os_rule('delete', rule)
            audit('expired', rule, 'warn', 'expired while the app was stopped')
            continue
        if rule['action'] == 'deny' and privileged:
            present, _ = apply_os_rule('check', rule)
            if present:
                rule['enforced'] = True
            else:
                # Linux drops iptables rules on reboot: put the saved block back
                note = 'was missing from the OS firewall' if rule.get('enforced') else 'now applied with admin/root rights'
                rule['enforced'], rule['last_command'] = apply_os_rule('add', rule)
                audit('restored', rule, 'ok' if rule['enforced'] else 'err', note)
        elif rule['action'] == 'deny' and rule.get('enforced'):
            rule['enforced'] = False
            rule['last_command'] = ''
            audit('restored', rule, 'warn', 'running without admin/root, so the OS rule could not be checked')
        firewall_rules.append(rule)
    for entry in load_json_lines(AUDIT_FILE)[-recent_audit.maxlen:]:
        recent_audit.append(entry)
    save_rules()


def load_json_lines(path):
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


# ---------- pages and connections ----------

@app.route('/')
def index():
    return render_template('index.html')


@socketio.on('connect')
def handle_connect():
    # Tell the page what it's running against, and restore rules and the log after a reload
    emit('server_info', server_info())
    with lock:
        emit('rules_update', list(firewall_rules))
        emit('audit_history', list(recent_audit))


@socketio.on('disconnect')
def handle_disconnect():
    with lock:
        if request.sid in active_scans:
            active_scans[request.sid]['cancel'] = True


# ---------- scanning ----------

def plan_chunks(target):
    """Split a target into groups of hosts for Nmap. Returns None if the range is too large."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]  # hostname
    if net.num_addresses > MAX_SCAN_HOSTS:
        return None
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
    return [' '.join(hosts[i:i + SCAN_CHUNK]) for i in range(0, len(hosts), SCAN_CHUNK)]


def scan_rows(nm):
    rows = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                info = nm[host][proto][port]
                rows.append({
                    'ip': host,
                    'port': port,
                    'proto': proto,
                    'service': info.get('name', ''),
                    'version': ' '.join(x for x in (info.get('product', ''), info.get('version', '')) if x),
                    'state': info['state'],
                    'status': info['state'],
                })
    return rows


def compare_with_last_scan(target, arguments, rows):
    """Compare open ports with the previous scan of the same target and scan type."""
    key = f'{target}|{arguments}'
    current = sorted({f"{r['ip']}:{r['port']}/{r['proto']}" for r in rows if r['state'] == 'open'})
    with lock:
        history = load_json(HISTORY_FILE, {})
        previous = history.get(key)
        history[key] = {'time': time.time(), 'open': current}
        save_json(HISTORY_FILE, history)
    if not previous:
        return {'previous_time': None, 'new_open': [], 'no_longer_open': []}
    before = set(previous['open'])
    return {'previous_time': previous['time'],
            'new_open': [p for p in current if p not in before],
            'no_longer_open': sorted(before - set(current))}


def run_scan(sid, target, arguments, chunks):
    found = []
    cancelled = False
    try:
        socketio.emit('scan_progress', {'done': 0, 'total': len(chunks)}, to=sid)
        for i, hosts in enumerate(chunks):
            with lock:
                cancelled = active_scans[sid]['cancel']
            if cancelled:
                break
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=hosts, arguments=arguments)
            except nmap.PortScannerError as e:
                # e.g. Nmap not installed, or SYN/UDP scans without admin/root privileges
                socketio.emit('scan_error', {'message': f'Scan failed: {e}'}, to=sid)
                return
            rows = scan_rows(nm)
            simulate_traffic(rows)
            for row in rows:
                socketio.emit('scan_update', row, to=sid)
            found += rows
            socketio.emit('scan_progress', {'done': i + 1, 'total': len(chunks)}, to=sid)

        if not found and not cancelled:
            socketio.emit('scan_update', {'ip': target, 'port': 'N/A', 'service': 'N/A',
                                          'status': 'No open ports found'}, to=sid)
        diff = None if cancelled else compare_with_last_scan(target, arguments, found)
        socketio.emit('scan_complete', {'target': target, 'arguments': arguments, 'count': len(found),
                                        'cancelled': cancelled, 'diff': diff}, to=sid)
    finally:
        with lock:
            active_scans.pop(sid, None)


# Handle scan request
@socketio.on('start_scan')
def handle_scan(data):
    target = parse_target(data.get('target_ip'))
    if target is None:
        emit('scan_error', {'message': 'Invalid target. Enter an IP address, CIDR range or hostname.'})
        return
    chunks = plan_chunks(target)
    if chunks is None:
        emit('scan_error', {'message': f'Range too large. Scan at most {MAX_SCAN_HOSTS} addresses (a /22) at a time.'})
        return
    arguments = SCAN_ARGS.get(data.get('scan_type'), DEFAULT_SCAN_ARGS)

    with lock:
        if request.sid in active_scans:
            emit('scan_error', {'message': 'A scan is already running. Wait for it or press Stop.'})
            return
        active_scans[request.sid] = {'cancel': False}
    # Run in the background so the page stays responsive and can add rules mid-scan
    socketio.start_background_task(run_scan, request.sid, target, arguments, chunks)


@socketio.on('stop_scan')
def handle_stop_scan():
    with lock:
        if request.sid in active_scans:
            active_scans[request.sid]['cancel'] = True


# ---------- firewall rules ----------

# Handle firewall rule creation
@socketio.on('add_firewall_rule')
def handle_firewall_rule(data):
    rule_ip = parse_source(data.get('ip'))
    ports = parse_ports(data.get('port'))
    rule_action = data.get('action')
    proto = str(data.get('proto') or 'tcp').lower()
    ok, seconds = parse_duration(data.get('duration'))

    if rule_ip is None:
        emit('firewall_error', {'message': 'Invalid source. Enter an IP address or a CIDR range like 10.0.0.0/24.'})
        return
    if ports is None:
        emit('firewall_error', {'message': 'Port must be 1-65535, or a range like 8000-8100.'})
        return
    if rule_action not in ACTIONS:
        emit('firewall_error', {'message': 'Action must be allow or deny.'})
        return
    if proto not in PROTOCOLS:
        emit('firewall_error', {'message': 'Protocol must be tcp or udp.'})
        return
    if not ok:
        emit('firewall_error', {'message': 'Expiry must be between 1 second and 7 days.'})
        return

    low, high = ports
    rule = {'id': uuid.uuid4().hex[:8], 'ip': rule_ip, 'port': low if low == high else f'{low}-{high}',
            'port_lo': low, 'port_hi': high, 'proto': proto, 'action': rule_action,
            'created_at': time.time(), 'expires_at': time.time() + seconds if seconds else None}

    # Deny rules are enforced at the OS level when the app has admin/root rights.
    # Without them the rule still works in the simulation, and the UI says so.
    # An allow rule removes a matching OS block if one exists.
    with lock:
        rule['enforced'], cmd = apply_os_rule('add' if rule_action == 'deny' else 'delete', rule)
        rule['command'] = cmd
        rule['last_command'] = cmd if rule['enforced'] else ''
        firewall_rules.append(rule)
        save_rules()
    audit('added', rule, 'ok' if rule['enforced'] or rule_action == 'allow' else 'warn',
          '' if rule['enforced'] or rule_action == 'allow' else 'no admin/root rights')

    # Emit the rule to the frontend for visualization
    emit('firewall_rule_added', rule)
    broadcast_rules()


@socketio.on('remove_firewall_rule')
def handle_remove_firewall_rule(data):
    with lock:
        rule = None
        if data.get('rule_id'):
            rule = next((r for r in firewall_rules if r['id'] == data['rule_id']), None)
        else:
            try:
                index = int(data.get('rule_number')) - 1  # Convert to 0-based index
            except (TypeError, ValueError):
                index = -1
            if 0 <= index < len(firewall_rules):
                rule = firewall_rules[index]
        if rule is None:
            emit('firewall_error', {'message': 'That rule no longer exists.'})
            return
        number = firewall_rules.index(rule) + 1
        remove_rule(rule, 'removed')

    emit('firewall_rule_removed', {'rule_number': number, 'rule': rule, 'command': rule['last_command']})
    broadcast_rules()


# Simulate traffic flow based on firewall rules
def simulate_traffic(scan_results):
    """Mark ports covered by a deny rule as Blocked; others keep their Nmap state."""
    with lock:
        rules = list(firewall_rules)
    for result in scan_results:
        result['blocked'] = False
        for rule in rules:
            # First matching rule wins, like most firewalls
            if rule_covers(rule, result['ip'], result['port'], result.get('proto', 'tcp')):
                if rule['action'] == 'deny':
                    result['status'] = 'Blocked'
                    result['blocked'] = True
                break


# Start the server
if __name__ == '__main__':
    restore_rules()
    socketio.start_background_task(expiry_loop)
    # Local-only tool: bound to 127.0.0.1 with the debugger off.
    # allow_unsafe_werkzeug lets the built-in dev server start outside a terminal.
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)
