import ipaddress
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as scanner  # noqa: E402


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Fresh rules, log and saved-state folder for each test."""
    monkeypatch.setattr(scanner, 'STATE_DIR', tmp_path)
    monkeypatch.setattr(scanner, 'RULES_FILE', tmp_path / 'firewall_rules.json')
    monkeypatch.setattr(scanner, 'AUDIT_FILE', tmp_path / 'block_log.jsonl')
    monkeypatch.setattr(scanner, 'HISTORY_FILE', tmp_path / 'scan_history.json')
    monkeypatch.setattr(scanner, 'SIEM_FILE', tmp_path / 'siem' / 'netscan-events.ndjson')
    monkeypatch.delenv('NETSCAN_SIEM_LOG', raising=False)
    scanner.firewall_rules.clear()
    scanner.recent_audit.clear()
    yield tmp_path
    scanner.firewall_rules.clear()


def address_set(text):
    """'a', 'a-b', 'a/24', 'a/255.255.255.0' or a comma list of them, as (first, last) integer pairs."""
    out = []
    for part in text.split(','):
        part = part.strip()
        if '-' in part:
            first, last = part.split('-')
            out.append((int(ipaddress.ip_address(first)), int(ipaddress.ip_address(last))))
        else:
            net = ipaddress.ip_network(part, strict=False)
            out.append((int(net.network_address), int(net.broadcast_address)))
    return out


def port_set(text):
    out = []
    for part in text.split(','):
        low, _, high = part.strip().partition('-')
        out.append((int(low), int(high or low)))
    return out


def in_sets(value, ranges):
    return any(lo <= value <= hi for lo, hi in ranges)


class FakeFirewall:
    """Stands in for iptables or netsh: keeps the rules the app writes and
    answers traffic questions the way the real firewall would."""

    def __init__(self, system):
        self.system = system
        self.chain = []    # iptables INPUT, top first
        self.netsh = {}    # rule name -> list of rule settings
        self.commands = []

    def run(self, cmd):
        self.commands.append(cmd)
        return self._iptables(cmd) if cmd[0] == 'iptables' else self._netsh(cmd)

    def _iptables(self, cmd):
        op = cmd[1]
        spec = tuple(cmd[4:] if op == '-I' else cmd[3:])  # -I INPUT 1 ... / -A INPUT ...
        if op == '-A':
            self.chain.append(spec)
            return True
        if op == '-I':
            self.chain.insert(0, spec)
            return True
        if op == '-C':
            return spec in self.chain
        if op == '-D':
            if spec in self.chain:
                self.chain.remove(spec)
                return True
            return False
        raise AssertionError(f'unexpected iptables command {cmd}')

    def _netsh(self, cmd):
        verb = cmd[3]
        args = dict(a.split('=', 1) for a in cmd[5:])
        name = args['name']
        if verb == 'add':
            self.netsh.setdefault(name, []).append(args)
            return True
        if verb == 'delete':
            return self.netsh.pop(name, None) is not None
        if verb == 'show':
            return name in self.netsh
        raise AssertionError(f'unexpected netsh command {cmd}')

    def blocks(self, ip, port, proto='tcp'):
        """Would the real firewall drop this inbound traffic?"""
        value = int(ipaddress.ip_address(ip))
        if self.system == 'Linux':
            for spec in self.chain:  # first matching rule wins
                s = dict(zip(spec[0::2], spec[1::2]))
                low, _, high = s['--dport'].partition(':')
                net = ipaddress.ip_network(s['-s'], strict=False)
                if s['-p'] == proto and int(low) <= port <= int(high or low) and ipaddress.ip_address(ip) in net:
                    return s['-j'] == 'DROP'
            return False
        # Windows: any matching block rule wins over every allow rule
        for rules in self.netsh.values():
            for r in rules:
                if (r['action'] == 'block' and r['protocol'].lower() == proto
                        and in_sets(value, address_set(r['remoteip'])) and in_sets(port, port_set(r['localport']))):
                    return True
        return False


@pytest.fixture(params=['Linux', 'Windows'])
def firewall(request, state, monkeypatch):
    """The app running with admin/root rights on Linux or Windows, against a fake OS firewall."""
    fake = FakeFirewall(request.param)
    monkeypatch.setattr(scanner, 'platform', types.SimpleNamespace(system=lambda: request.param))
    monkeypatch.setattr(scanner, 'is_privileged', lambda: True)
    monkeypatch.setattr(scanner, '_run', fake.run)
    return fake


@pytest.fixture
def client(state):
    c = scanner.socketio.test_client(scanner.app)
    c.get_received()
    yield c
    c.disconnect()
