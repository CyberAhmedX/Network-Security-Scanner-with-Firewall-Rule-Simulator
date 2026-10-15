"""Tests against the real OS firewall. They change firewall rules, so they only run
when REAL_FIREWALL=1 is set and the tests run as root (Linux) or Administrator (Windows).
GitHub Actions runs them on throwaway Linux and Windows machines."""
import os
import platform
import socket
import subprocess
import threading

import pytest

import app as scanner
from conftest import address_set, in_sets, port_set

pytestmark = pytest.mark.skipif(os.environ.get('REAL_FIREWALL') != '1',
                                reason='set REAL_FIREWALL=1 and run as root/Administrator to test the real firewall')


@pytest.fixture(autouse=True)
def needs_rights():
    # Asked for real firewall tests: fail loudly rather than skip if they can't really run
    assert scanner.is_privileged(), 'REAL_FIREWALL=1 needs root (Linux) or Administrator (Windows)'


def add(client, ip, port, action='deny', proto='tcp'):
    client.emit('add_firewall_rule', {'ip': ip, 'port': port, 'action': action, 'proto': proto, 'duration': ''})
    added = [e['args'][0] for e in client.get_received() if e['name'] == 'firewall_rule_added']
    assert added and added[0]['enforced'], f'rule was not applied: {added}'
    return added[0]


def remove(client, rule_id):
    client.emit('remove_firewall_rule', {'rule_id': rule_id})
    client.get_received()


@pytest.fixture
def cleanup(client):
    """Remove every rule the test added, even when it fails halfway."""
    yield
    for r in list(scanner.firewall_rules):
        remove(client, r['id'])


# ---------------------------------------------------------------- Linux: real traffic

@pytest.fixture
def listener():
    """A TCP server on 127.0.0.1 that accepts connections in the background."""
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(16)
    stop = threading.Event()

    def serve():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join()
    server.close()


def connects(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=1.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(platform.system() != 'Linux', reason='Linux only')
def test_linux_allow_opens_one_address_in_a_blocked_range(client, cleanup, listener):
    port = listener
    assert connects(port)

    deny = add(client, '127.0.0.0/8', port)
    assert not connects(port), 'the deny rule should drop the connection'

    allow = add(client, '127.0.0.1', port, 'allow')
    assert connects(port), 'the allow rule should win over the deny rule'

    remove(client, allow['id'])
    assert not connects(port), 'removing the allow rule should bring the block back'

    remove(client, deny['id'])
    assert connects(port)
    rules = subprocess.run(['iptables', '-S', 'INPUT'], capture_output=True, text=True).stdout
    assert f'--dport {port} ' not in rules + ' ', 'no rules should be left behind'


# ---------------------------------------------------------------- Windows: real Windows Firewall rules

def netsh_rules(name):
    """Settings of every Windows Firewall rule with this name, from netsh's own output."""
    out = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={name}'],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return []
    rules, current = [], None
    for line in out.stdout.splitlines():
        key, sep, value = line.partition(':')
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == 'Rule Name':
            current = {}
            rules.append(current)
        elif current is not None:
            current[key] = value
    return rules


def windows_blocks(deny_id, ip, port):
    value = int(scanner.ipaddress.ip_address(ip))
    for r in netsh_rules(f'NetScanner-deny-{deny_id}'):
        assert r['Action'] == 'Block' and r['Direction'] == 'In'
        if in_sets(value, address_set(r['RemoteIP'])) and in_sets(port, port_set(r['LocalPort'])):
            return True
    return False


@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows only')
def test_windows_allow_cuts_a_hole_in_the_block(client, cleanup):
    # 198.51.100.0/24 is reserved for documentation, so no real traffic is affected
    deny = add(client, '198.51.100.0/24', '8000-8100')
    assert windows_blocks(deny['id'], '198.51.100.50', 8050)

    allow = add(client, '198.51.100.50', 8050, 'allow')
    allow_rules = netsh_rules(f"NetScanner-allow-{allow['id']}")
    assert len(allow_rules) == 1 and allow_rules[0]['Action'] == 'Allow'

    # Windows lets a block win over an allow, so the block itself must leave the allowed traffic out
    assert not windows_blocks(deny['id'], '198.51.100.50', 8050)
    assert windows_blocks(deny['id'], '198.51.100.50', 8049)
    assert windows_blocks(deny['id'], '198.51.100.50', 8051)
    assert windows_blocks(deny['id'], '198.51.100.49', 8050)
    assert windows_blocks(deny['id'], '198.51.100.51', 8050)
    assert windows_blocks(deny['id'], '198.51.100.0', 8000)
    assert windows_blocks(deny['id'], '198.51.100.255', 8100)

    remove(client, allow['id'])
    assert netsh_rules(f"NetScanner-allow-{allow['id']}") == []
    assert windows_blocks(deny['id'], '198.51.100.50', 8050), 'removing the allow rule should restore the block'

    remove(client, deny['id'])
    assert netsh_rules(f"NetScanner-deny-{deny['id']}") == []


@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows only')
def test_windows_allow_covering_the_whole_block(client, cleanup):
    deny = add(client, '198.51.100.7', 9000)
    assert windows_blocks(deny['id'], '198.51.100.7', 9000)
    add(client, '198.51.100.0/24', '9000-9010', 'allow')
    assert netsh_rules(f"NetScanner-deny-{deny['id']}") == [], 'nothing should be left to block'
