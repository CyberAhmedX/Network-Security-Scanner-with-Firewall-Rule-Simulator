import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
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
# Events for a SIEM (Wazuh, Elastic, Splunk...), one JSON object per line in Elastic Common Schema.
# NETSCAN_SIEM_LOG=/path/file.ndjson writes them elsewhere, NETSCAN_SIEM_LOG=off turns them off.
SIEM_FILE = STATE_DIR / 'siem' / 'netscan-events.ndjson'
ECS_VERSION = '8.11.0'

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


def local_addresses():
    """This computer's own IP addresses: loopback plus its network addresses."""
    addrs = {'127.0.0.1', '::1'}
    try:
        addrs.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        # Connecting a UDP socket sends nothing; it only picks the outgoing interface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 9))
            addrs.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(addrs)


def covered_local_addresses(rule):
    """Local addresses a deny rule would block. Scans from this computer use them as their source,
    so the OS firewall would drop the scanner's own probes and hide those ports."""
    if rule['action'] != 'deny':
        return []
    try:
        net = ipaddress.ip_network(rule['ip'], strict=False)
    except ValueError:
        return []
    return [a for a in local_addresses() if ipaddress.ip_address(a) in net]


def server_info():
    return {'os': platform.system(), 'privileged': is_privileged(), 'max_scan_hosts': MAX_SCAN_HOSTS,
            'local_addresses': local_addresses()}


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
    siem_rule_event(event, rule, level, note)
    socketio.emit('audit', entry)


def broadcast_rules():
    with lock:
        rules = list(firewall_rules)
    socketio.emit('rules_update', rules)


# ---------- SIEM events ----------
#
# Every scan, port result, new open port and firewall rule change is written as one
# Elastic Common Schema (ECS) event per line. Wazuh, Filebeat/Elastic Agent and Splunk
# can all read the file as it grows; the siem/ folder has ready-made configs and rules.

def iso_time(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def siem_path():
    setting = os.environ.get('NETSCAN_SIEM_LOG', '').strip()
    if setting.lower() in ('off', 'false', '0', 'no'):
        return None
    return Path(setting) if setting else SIEM_FILE


def observer():
    return {'hostname': socket.gethostname(), 'type': 'scanner', 'vendor': 'CyberAhmedX',
            'product': 'Network Security Scanner', 'os': {'family': platform.system().lower()}}


def siem_event(action, kind, category, types, message, outcome=None, severity=None,
               dataset='netscan.scan', **fields):
    """Append one ECS event to the SIEM log. Extra keyword arguments become top-level ECS fields."""
    path = siem_path()
    if path is None:
        return None
    now = time.time()
    event = {'@timestamp': iso_time(now), 'ecs': {'version': ECS_VERSION},
             'event': {'module': 'netscan', 'dataset': dataset, 'kind': kind, 'category': category,
                       'type': types, 'action': action, 'created': iso_time(now)},
             'message': message, 'observer': observer()}
    if outcome:
        event['event']['outcome'] = outcome
    if severity is not None:
        event['event']['severity'] = severity
    for key, value in fields.items():
        if isinstance(value, dict) and isinstance(event.get(key), dict):
            event[key].update(value)
        else:
            event[key] = value
    with lock:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
        except OSError as e:
            print(f"Could not write SIEM event: {e}")
    return event


def ip_fields(value):
    """ECS keeps single addresses in .ip and anything else (ranges, hostnames) in .address."""
    try:
        return {'ip': str(ipaddress.ip_address(value)), 'address': str(value)}
    except ValueError:
        return {'address': str(value)}


RULE_EVENT_TYPES = {'added': 'creation', 'removed': 'deletion', 'expired': 'deletion', 'restored': 'change'}


def siem_rule_event(event, rule, level, note):
    enforced = bool(rule.get('enforced'))
    supported = platform.system() in ('Linux', 'Windows')
    if enforced:
        mode, outcome = 'enforced', 'success'
    elif level == 'err' or (event == 'added' and supported and is_privileged()):
        mode, outcome = 'failed', 'failure'  # had the rights, but the OS firewall command failed
    else:
        mode, outcome = 'simulated', 'unknown'
    severity = {'added': 5 if rule['action'] == 'allow' else 3, 'removed': 3, 'expired': 2, 'restored': 2}.get(event, 3)
    if outcome == 'failure':
        severity = 6
    ruleset = {'Linux': 'iptables', 'Windows': 'windows-firewall'}.get(platform.system(), 'none') if enforced else 'simulation'
    destination = {'port': rule['port_lo']} if rule.get('port_lo') == rule.get('port_hi') and rule.get('port_lo') else {}
    siem_event(
        f'firewall-rule-{event}', 'event', ['configuration', 'network'], [RULE_EVENT_TYPES.get(event, 'change')],
        f"Firewall rule {event}: {rule_label(rule)}" + (f" ({note})" if note else ''),
        outcome=outcome, severity=severity, dataset='netscan.firewall',
        rule={'id': rule.get('id'), 'name': rule_label(rule), 'ruleset': ruleset},
        source=ip_fields(rule['ip']), destination=destination, network={'transport': rule['proto']},
        netscan={'rule': {'action': rule['action'], 'source': rule['ip'], 'ports': str(rule['port']),
                          'mode': mode, 'command': rule.get('last_command', ''),
                          'expires_at': iso_time(rule['expires_at']) if rule.get('expires_at') else None,
                          'covers_self': rule.get('covers_self', []), 'note': note}})


def split_port_key(key):
    """'10.0.0.5:22/tcp' -> ('10.0.0.5', 22, 'tcp'). rsplit keeps IPv6 addresses whole."""
    address, rest = key.rsplit(':', 1)
    port, proto = rest.split('/', 1)
    return address, int(port), proto


def siem_scan_events(scan_id, target, arguments, rows, diff, started, cancelled):
    scan = {'id': scan_id, 'target': target, 'arguments': arguments}
    for row in rows:
        siem_event('port-state', 'event', ['network'], ['info'],
                   f"{row['ip']}:{row['port']}/{row['proto']} is {row['state']}" + (' (blocked by a rule)' if row.get('blocked') else ''),
                   destination=ip_fields(row['ip']) | {'port': row['port']}, network={'transport': row['proto']},
                   service={'name': row.get('service') or None, 'version': row.get('version') or None},
                   netscan={'scan': scan, 'port': {'state': row['state'], 'blocked_by_rule': bool(row.get('blocked'))}})
    counts = {state: sum(1 for r in rows if r['state'] == state) for state in ('open', 'filtered', 'closed')}
    counts['blocked_by_rule'] = sum(1 for r in rows if r.get('blocked'))
    ended = time.time()
    siem_event('scan-stopped' if cancelled else 'scan-completed', 'event', ['network'], ['end'],
               f"Nmap {arguments} scan of {target} {'stopped' if cancelled else 'completed'}: "
               f"{counts['open']} open, {len(rows)} reported",
               outcome='unknown' if cancelled else 'success', severity=1,
               netscan={'scan': scan | counts | {'reported': len(rows)}},
               **{'event': {'start': iso_time(started), 'end': iso_time(ended), 'duration': int((ended - started) * 1e9)}})
    if not diff:
        return
    previous = iso_time(diff['previous_time']) if diff.get('previous_time') else None
    for key in diff.get('new_open', []):
        ip, port, proto = split_port_key(key)
        siem_event('new-open-port', 'alert', ['network'], ['info'],
                   f"New open port since the last scan: {key}", severity=7,
                   destination=ip_fields(ip) | {'port': port}, network={'transport': proto},
                   netscan={'scan': scan | {'previous_scan': previous}})
    for key in diff.get('no_longer_open', []):
        ip, port, proto = split_port_key(key)
        siem_event('port-no-longer-open', 'event', ['network'], ['info'],
                   f"Port no longer open since the last scan: {key}", severity=3,
                   destination=ip_fields(ip) | {'port': port}, network={'transport': proto},
                   netscan={'scan': scan | {'previous_scan': previous}})


# ---------- real firewall enforcement ----------
#
# Allow rules always take priority over deny rules, in the OS firewall and in
# the simulation alike, so allowing one address inside a blocked range works.
#
# Linux (iptables): deny rules are appended as DROP rules and allow rules are
# inserted at the top of INPUT as ACCEPT rules. iptables uses the first rule
# that matches, so an ACCEPT always wins.
#
# Windows (netsh advfirewall): a block rule beats an allow rule no matter the
# order, so an allow rule alone can't make a hole in a block. Each deny rule is
# therefore written as its range with every overlapping allow rule cut out,
# and rewritten whenever allow rules change. Allow rules are also added as real
# allow rules, since Windows drops unsolicited inbound traffic by default.

def _run(cmd):
    """Run a command without a shell. Returns True if it exited successfully."""
    if cmd[0] == 'iptables' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        # -n: fail instead of waiting for a password prompt when not run as root
        cmd = ['sudo', '-n'] + cmd
    try:
        return subprocess.run(cmd, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"Error running {cmd[0]}: {e}")
        return False


def port_text(low, high, sep='-'):
    return str(low) if low == high else f'{low}{sep}{high}'


def iptables_command(op, rule):
    """Argument list to add, delete or check a rule's iptables entry. op: 'add', 'delete' or 'check'."""
    target = 'ACCEPT' if rule['action'] == 'allow' else 'DROP'
    if op == 'add':
        # ACCEPT goes to the top so it wins over any DROP; DROP goes to the end
        position = ['-I', 'INPUT', '1'] if target == 'ACCEPT' else ['-A', 'INPUT']
    else:
        position = ['-D' if op == 'delete' else '-C', 'INPUT']
    return ['iptables'] + position + ['-p', rule['proto'], '--dport', port_text(rule['port_lo'], rule['port_hi'], ':'),
                                      '-s', rule['ip'], '-j', target]


def windows_rule_name(rule):
    return f"NetScanner-{rule['action']}-{rule['id']}"


def legacy_windows_name(rule):
    """Name used for block rules before rule IDs were part of the name."""
    return f"Block_{rule['ip'].replace('/', '_')}_{port_text(rule['port_lo'], rule['port_hi'])}_{rule['proto']}"


# Address and port ranges as plain integer intervals, so a deny range can have
# allowed parts cut out of it. A box is (ip version, first ip, last ip, first port, last port).

def rule_box(rule):
    net = ipaddress.ip_network(rule['ip'], strict=False)
    return (net.version, int(net.network_address), int(net.broadcast_address), rule['port_lo'], rule['port_hi'])


def subtract_box(box, cut):
    """Parts of `box` not covered by `cut`, as a list of boxes (at most four)."""
    ver, ip_lo, ip_hi, p_lo, p_hi = box
    c_ver, c_ip_lo, c_ip_hi, c_p_lo, c_p_hi = cut
    if ver != c_ver or c_ip_hi < ip_lo or c_ip_lo > ip_hi or c_p_hi < p_lo or c_p_lo > p_hi:
        return [box]  # no overlap
    parts = []
    if ip_lo < c_ip_lo:
        parts.append((ver, ip_lo, c_ip_lo - 1, p_lo, p_hi))
    if c_ip_hi < ip_hi:
        parts.append((ver, c_ip_hi + 1, ip_hi, p_lo, p_hi))
    mid_lo, mid_hi = max(ip_lo, c_ip_lo), min(ip_hi, c_ip_hi)
    if p_lo < c_p_lo:
        parts.append((ver, mid_lo, mid_hi, p_lo, c_p_lo - 1))
    if c_p_hi < p_hi:
        parts.append((ver, mid_lo, mid_hi, c_p_hi + 1, p_hi))
    return parts


def overlaps(a, b):
    """True if two rules share a protocol and at least one address and port."""
    if a['proto'] != b['proto']:
        return False
    return subtract_box(rule_box(a), rule_box(b)) != [rule_box(a)]


def blocked_boxes(deny, allows):
    """What a deny rule still blocks once every overlapping allow rule is cut out."""
    boxes = [rule_box(deny)]
    for allow in allows:
        if allow['proto'] != deny['proto']:
            continue
        cut = rule_box(allow)
        boxes = [part for box in boxes for part in subtract_box(box, cut)]
    return boxes


def address_text(ver, low, high):
    """One address, a CIDR range if it is exactly one, otherwise first-last."""
    cls = ipaddress.IPv4Address if ver == 4 else ipaddress.IPv6Address
    first, last = cls(low), cls(high)
    if low == high:
        return str(first)
    nets = list(ipaddress.summarize_address_range(first, last))
    return str(nets[0]) if len(nets) == 1 else f'{first}-{last}'


def windows_block_specs(deny, allows):
    """(remoteip, localport) pairs for the netsh block rules of one deny rule.

    Parts with the same address range are joined into one port list, then parts
    with the same port list into one address list, so few netsh rules are needed."""
    by_address = {}
    for ver, ip_lo, ip_hi, p_lo, p_hi in sorted(blocked_boxes(deny, allows)):
        by_address.setdefault((ver, ip_lo, ip_hi), []).append((p_lo, p_hi))
    by_ports = {}
    for address, ports in by_address.items():
        by_ports.setdefault(tuple(sorted(ports)), []).append(address)
    return [(','.join(address_text(*a) for a in addresses), ','.join(port_text(lo, hi) for lo, hi in ports))
            for ports, addresses in by_ports.items()]


def netsh_add(rule, remoteip, localport):
    action = 'allow' if rule['action'] == 'allow' else 'block'
    return ['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={windows_rule_name(rule)}', 'dir=in',
            f'action={action}', f"protocol={rule['proto'].upper()}", f'remoteip={remoteip}', f'localport={localport}']


def netsh_delete(rule):
    return ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={windows_rule_name(rule)}']


def netsh_show(rule):
    return ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={windows_rule_name(rule)}']


def active_allows():
    return [r for r in firewall_rules if r['action'] == 'allow']


def os_add_commands(rule):
    """Commands that put one rule into the OS firewall. Empty on unsupported systems."""
    system = platform.system()
    if system == 'Linux':
        return [iptables_command('add', rule)]
    if system == 'Windows':
        if rule['action'] == 'allow':
            return [netsh_add(rule, rule['ip'], port_text(rule['port_lo'], rule['port_hi']))]
        return [netsh_add(rule, ip, ports) for ip, ports in windows_block_specs(rule, active_allows())]
    return []


def enforce(rule):
    """Add a rule to the OS firewall. Sets rule['enforced'] and rule['last_command']."""
    system = platform.system()
    if system not in ('Linux', 'Windows'):
        rule['enforced'], rule['last_command'] = False, ''
        return False
    commands = os_add_commands(rule)
    if system == 'Windows':
        _run(netsh_delete(rule))  # replace any earlier version of this rule's parts
    ok = all([_run(cmd) for cmd in commands])
    rule['enforced'] = ok
    rule['last_command'] = ' ; '.join(' '.join(cmd) for cmd in commands) if commands else \
        ' '.join(netsh_delete(rule)) + '  (fully covered by allow rules, nothing left to block)'
    return ok


def unenforce(rule):
    """Remove a rule from the OS firewall. Sets rule['last_command']."""
    system = platform.system()
    if system == 'Linux':
        cmd = iptables_command('delete', rule)
    elif system == 'Windows':
        cmd = netsh_delete(rule)
    else:
        rule['last_command'] = ''
        return False
    ok = _run(cmd)
    rule['last_command'] = ' '.join(cmd)
    return ok


def is_present(rule):
    system = platform.system()
    if system == 'Linux':
        return _run(iptables_command('check', rule))
    if system == 'Windows':
        if rule['action'] == 'deny' and not os_add_commands(rule):
            return True  # nothing to block: being absent is correct
        return _run(netsh_show(rule))
    return False


def refresh_windows_blocks(changed_allow):
    """On Windows, rewrite the deny rules an allow rule overlaps, so the allowed part is cut out or put back."""
    if platform.system() != 'Windows':
        return
    for rule in firewall_rules:
        if rule['action'] == 'deny' and rule.get('enforced') and overlaps(rule, changed_allow):
            enforce(rule)


def annotate_rules():
    """Note on each deny rule which allow rules take priority over part of it, for the rule list."""
    allows = active_allows()
    for rule in firewall_rules:
        if rule['action'] != 'deny':
            continue
        over = [a['id'] for a in allows if overlaps(rule, a)]
        rule['overridden_by'] = over
        rule['fully_allowed'] = bool(over) and not blocked_boxes(rule, allows)


def rule_covers(rule, ip, port, proto):
    """True if the rule's source, port range and protocol all match this traffic."""
    if rule.get('proto', 'tcp') != proto or not rule['port_lo'] <= port <= rule['port_hi']:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(rule['ip'], strict=False)
    except ValueError:
        return False


def is_blocked(rules, ip, port, proto):
    """Blocked when a deny rule matches and no allow rule does: allow always wins."""
    matching = [r for r in rules if rule_covers(r, ip, port, proto)]
    return any(r['action'] == 'deny' for r in matching) and not any(r['action'] == 'allow' for r in matching)


def remove_rule(rule, event, note=''):
    """Take a rule out of the list and the OS firewall, then log it. Caller holds the lock."""
    firewall_rules.remove(rule)
    if rule.get('enforced'):
        unenforce(rule)
        if rule['action'] == 'allow':
            refresh_windows_blocks(rule)  # the block comes back where this rule had cut it out
    else:
        rule['last_command'] = ''
    annotate_rules()
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
    saved = []
    for rule in load_json(RULES_FILE, []):
        rule.setdefault('proto', 'tcp')
        rule.setdefault('id', uuid.uuid4().hex[:8])
        try:
            rule_box(rule)
        except (KeyError, TypeError, ValueError):
            print(f"Skipping a damaged saved rule: {rule}")
            continue
        if rule.get('expires_at') and rule['expires_at'] <= now:
            if rule.get('enforced'):
                unenforce(rule)
            audit('expired', rule, 'warn', 'expired while the app was stopped')
            continue
        saved.append(rule)

    # Allow rules first, so the Windows block rules are written with them cut out
    for rule in sorted(saved, key=lambda r: r['action'] != 'allow'):
        rule['covers_self'] = covered_local_addresses(rule)
        firewall_rules.append(rule)
        was_enforced = rule.get('enforced')
        if privileged:
            # Windows block rules are always rewritten, so they match the current allow rules
            windows_deny = platform.system() == 'Windows' and rule['action'] == 'deny'
            if windows_deny:
                _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={legacy_windows_name(rule)}'])
            if windows_deny or not is_present(rule):
                # Linux drops iptables rules on reboot: put the saved rule back
                enforce(rule)
                if not (windows_deny and was_enforced and rule['enforced']):
                    note = 'was missing from the OS firewall' if was_enforced else 'now applied with admin/root rights'
                    audit('restored', rule, 'ok' if rule['enforced'] else 'err', note)
            else:
                rule['enforced'] = True
        elif was_enforced:
            rule['enforced'] = False
            rule['last_command'] = ''
            audit('restored', rule, 'warn', 'running without admin/root, so the OS rule could not be checked')
    firewall_rules.sort(key=lambda r: r.get('created_at', 0))
    annotate_rules()
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
    scan_id = uuid.uuid4().hex[:12]
    started = time.time()
    siem_event('scan-started', 'event', ['network'], ['start'], f"Nmap {arguments} scan of {target} started",
               netscan={'scan': {'id': scan_id, 'target': target, 'arguments': arguments}})
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
                siem_event('scan-failed', 'event', ['network'], ['end'], f"Nmap {arguments} scan of {target} failed",
                           outcome='failure', severity=4, error={'message': str(e)},
                           netscan={'scan': {'id': scan_id, 'target': target, 'arguments': arguments}})
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
        siem_scan_events(scan_id, target, arguments, found, diff, started, cancelled)
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
    rule['covers_self'] = covered_local_addresses(rule)

    # With admin/root rights the rule goes into the OS firewall too. Without them it
    # still works in the simulation, and the page says so.
    with lock:
        firewall_rules.append(rule)
        enforce(rule)
        rule['command'] = rule['last_command']
        if rule['enforced'] and rule_action == 'allow':
            refresh_windows_blocks(rule)  # cut this range out of overlapping Windows block rules
        if not rule['enforced']:
            rule['last_command'] = ''
        annotate_rules()
        save_rules()
    supported = platform.system() in ('Linux', 'Windows')
    audit('added', rule, 'ok' if rule['enforced'] else 'warn',
          '' if rule['enforced'] else ('no admin/root rights' if supported else 'no supported OS firewall'))

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
    """Mark ports a deny rule blocks as Blocked; others keep their Nmap state. Allow rules win over deny rules."""
    with lock:
        rules = list(firewall_rules)
    for result in scan_results:
        result['blocked'] = is_blocked(rules, result['ip'], result['port'], result.get('proto', 'tcp'))
        if result['blocked']:
            result['status'] = 'Blocked'


# Start the server
if __name__ == '__main__':
    restore_rules()
    socketio.start_background_task(expiry_loop)
    # Local-only tool: bound to 127.0.0.1 with the debugger off.
    # allow_unsafe_werkzeug lets the built-in dev server start outside a terminal.
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)
