"""Allow and deny rules: the rule math, the OS commands, and what the firewall ends up doing."""
import json

import pytest

import app as scanner
from conftest import FakeFirewall


def rule(ip, ports, action='deny', proto='tcp', rule_id=None):
    low, _, high = str(ports).partition('-')
    low, high = int(low), int(high or low)
    return {'id': rule_id or f'{action}{ip}{ports}', 'ip': ip, 'port': ports, 'port_lo': low, 'port_hi': high,
            'proto': proto, 'action': action}


def add(client, ip, port, action='deny', proto='tcp', duration=''):
    client.emit('add_firewall_rule', {'ip': ip, 'port': port, 'action': action, 'proto': proto, 'duration': duration})
    events = client.get_received()
    added = [e['args'][0] for e in events if e['name'] == 'firewall_rule_added']
    errors = [e['args'][0]['message'] for e in events if e['name'] == 'firewall_error']
    assert not errors, errors
    return added[0]


def remove(client, rule_id):
    client.emit('remove_firewall_rule', {'rule_id': rule_id})
    client.get_received()


def simulated(ip, port, proto='tcp'):
    rows = [{'ip': ip, 'port': port, 'proto': proto, 'status': 'open'}]
    scanner.simulate_traffic(rows)
    return rows[0]['blocked']


# ---------------------------------------------------------------- rule math

def test_cut_one_address_and_port_out_of_a_range():
    deny = rule('10.0.0.0/24', '8000-8100')
    allow = rule('10.0.0.50', 8050, 'allow')
    assert scanner.windows_block_specs(deny, [allow]) == [
        ('10.0.0.0-10.0.0.49,10.0.0.51-10.0.0.255', '8000-8100'),
        ('10.0.0.50', '8000-8049,8051-8100'),
    ]


def test_cut_half_a_network_leaves_a_cidr():
    deny = rule('10.0.0.0/24', 22)
    assert scanner.windows_block_specs(deny, [rule('10.0.0.0/25', 22, 'allow')]) == [('10.0.0.128/25', '22')]


def test_allow_covering_everything_leaves_nothing_to_block():
    deny = rule('10.0.0.0/24', '80-90')
    assert scanner.windows_block_specs(deny, [rule('10.0.0.0/16', '1-65535', 'allow')]) == []


def test_other_protocol_and_ip_version_are_not_cut():
    deny = rule('10.0.0.0/24', 53)
    others = [rule('10.0.0.5', 53, 'allow', proto='udp'), rule('::1', 53, 'allow')]
    assert scanner.windows_block_specs(deny, others) == [('10.0.0.0/24', '53')]


def test_ipv6_ranges_are_cut_too():
    deny = rule('2001:db8::/120', 443)
    assert scanner.windows_block_specs(deny, [rule('2001:db8::80/121', 443, 'allow')]) == [('2001:db8::/121', '443')]


def test_several_allow_rules():
    deny = rule('192.168.1.0/24', 22)
    allows = [rule('192.168.1.10', 22, 'allow'), rule('192.168.1.20', 22, 'allow')]
    assert scanner.windows_block_specs(deny, allows) == [
        ('192.168.1.0-192.168.1.9,192.168.1.11-192.168.1.19,192.168.1.21-192.168.1.255', '22')]


def test_allow_wins_in_the_simulation():
    rules = [rule('10.0.0.0/24', 22), rule('10.0.0.5', 22, 'allow')]
    assert scanner.is_blocked(rules, '10.0.0.6', 22, 'tcp')
    assert not scanner.is_blocked(rules, '10.0.0.5', 22, 'tcp')
    assert not scanner.is_blocked(rules, '10.0.0.6', 23, 'tcp')
    assert not scanner.is_blocked(rules, '10.0.0.6', 22, 'udp')
    # order doesn't matter: allow added first still wins
    assert not scanner.is_blocked(list(reversed(rules)), '10.0.0.5', 22, 'tcp')


def test_iptables_commands():
    deny, allow = rule('10.0.0.0/24', '8000-8100'), rule('10.0.0.5', 22, 'allow')
    assert scanner.iptables_command('add', deny) == \
        ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '8000:8100', '-s', '10.0.0.0/24', '-j', 'DROP']
    assert scanner.iptables_command('add', allow) == \
        ['iptables', '-I', 'INPUT', '1', '-p', 'tcp', '--dport', '22', '-s', '10.0.0.5', '-j', 'ACCEPT']
    assert scanner.iptables_command('delete', allow)[:3] == ['iptables', '-D', 'INPUT']
    assert scanner.iptables_command('check', deny)[:3] == ['iptables', '-C', 'INPUT']


def test_netsh_commands():
    allow = rule('10.0.0.5', 22, 'allow', rule_id='abc123')
    assert scanner.netsh_add(allow, '10.0.0.5', '22') == [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=NetScanner-allow-abc123', 'dir=in',
        'action=allow', 'protocol=TCP', 'remoteip=10.0.0.5', 'localport=22']
    assert scanner.netsh_delete(allow) == ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                                           'name=NetScanner-allow-abc123']


# ---------------------------------------------------------------- the whole flow, on Linux and on Windows

def test_allow_one_address_inside_a_blocked_range(firewall, client):
    deny = add(client, '10.0.0.0/24', 22)
    assert deny['enforced']
    assert firewall.blocks('10.0.0.5', 22) and firewall.blocks('10.0.0.6', 22)

    allow = add(client, '10.0.0.5', 22, 'allow')
    assert allow['enforced']
    assert not firewall.blocks('10.0.0.5', 22)  # the allowed address gets through
    assert firewall.blocks('10.0.0.6', 22)      # the rest of the range stays blocked
    assert not simulated('10.0.0.5', 22) and simulated('10.0.0.6', 22)

    remove(client, allow['id'])
    assert firewall.blocks('10.0.0.5', 22)      # removing the allow brings the block back
    assert simulated('10.0.0.5', 22)

    remove(client, deny['id'])
    assert not firewall.blocks('10.0.0.6', 22)
    assert firewall.chain == [] and firewall.netsh == {}


def test_allow_added_before_the_deny_still_wins(firewall, client):
    add(client, '10.0.0.5', 22, 'allow')
    add(client, '10.0.0.0/24', 22)
    assert not firewall.blocks('10.0.0.5', 22)
    assert firewall.blocks('10.0.0.9', 22)


def test_allow_part_of_a_port_range(firewall, client):
    add(client, '172.16.0.10', '8000-8100')
    add(client, '172.16.0.10', '8050-8060', 'allow')
    assert firewall.blocks('172.16.0.10', 8049) and firewall.blocks('172.16.0.10', 8061)
    assert not firewall.blocks('172.16.0.10', 8055)


def test_exact_allow_unblocks_and_the_deny_still_shows_as_overridden(firewall, client):
    deny = add(client, '192.168.1.50', 22)
    add(client, '192.168.1.50', 22, 'allow')
    assert not firewall.blocks('192.168.1.50', 22)
    saved = {r['id']: r for r in scanner.firewall_rules}[deny['id']]
    assert saved['fully_allowed'] and len(saved['overridden_by']) == 1


def test_allow_for_another_protocol_does_not_unblock(firewall, client):
    add(client, '10.0.0.0/24', 53, proto='udp')
    add(client, '10.0.0.5', 53, 'allow', proto='tcp')
    assert firewall.blocks('10.0.0.5', 53, 'udp')


def test_expired_allow_rule_restores_the_block(firewall, client, monkeypatch):
    add(client, '10.0.0.0/24', 22)
    add(client, '10.0.0.5', 22, 'allow', duration=60)
    assert not firewall.blocks('10.0.0.5', 22)
    monkeypatch.setattr(scanner.time, 'time', lambda: 4102444800)  # far in the future
    scanner.expire_due_rules()
    assert firewall.blocks('10.0.0.5', 22)
    assert [r['action'] for r in scanner.firewall_rules] == ['deny']


def test_windows_rewrites_only_overlapping_blocks(state, monkeypatch, client):
    fake = FakeFirewall('Windows')
    monkeypatch.setattr(scanner, 'platform', type('P', (), {'system': staticmethod(lambda: 'Windows')}))
    monkeypatch.setattr(scanner, 'is_privileged', lambda: True)
    monkeypatch.setattr(scanner, '_run', fake.run)
    near = add(client, '10.0.0.0/24', 22)
    far = add(client, '10.9.9.0/24', 22)
    fake.commands.clear()
    add(client, '10.0.0.5', 22, 'allow')
    touched = {c[5] for c in fake.commands}
    assert f"name=NetScanner-deny-{near['id']}" in touched       # cut around the allowed address
    assert f"name=NetScanner-deny-{far['id']}" not in touched    # no overlap: left alone


def test_restore_after_restart_rebuilds_the_firewall(firewall, client):
    add(client, '10.0.0.0/24', 22)
    add(client, '10.0.0.5', 22, 'allow')
    # A reboot wipes iptables; on Windows the rules stay but are rewritten anyway
    firewall.chain.clear()
    scanner.firewall_rules.clear()
    scanner.restore_rules()
    assert [r['action'] for r in scanner.firewall_rules] == ['deny', 'allow']  # original order kept
    assert all(r['enforced'] for r in scanner.firewall_rules)
    assert not firewall.blocks('10.0.0.5', 22) and firewall.blocks('10.0.0.6', 22)


def test_restore_removes_old_windows_block_names(state, monkeypatch):
    fake = FakeFirewall('Windows')
    monkeypatch.setattr(scanner, 'platform', type('P', (), {'system': staticmethod(lambda: 'Windows')}))
    monkeypatch.setattr(scanner, 'is_privileged', lambda: True)
    monkeypatch.setattr(scanner, '_run', fake.run)
    old = rule('10.0.0.0/24', 22, rule_id='legacy01')
    old['enforced'] = True
    fake.netsh['Block_10.0.0.0_24_22_tcp'] = [{'action': 'block', 'protocol': 'TCP', 'remoteip': '10.0.0.0/24',
                                               'localport': '22'}]
    scanner.RULES_FILE.write_text(json.dumps([old]))
    scanner.restore_rules()
    assert 'Block_10.0.0.0_24_22_tcp' not in fake.netsh
    assert 'NetScanner-deny-legacy01' in fake.netsh


# ---------------------------------------------------------------- without admin/root rights

@pytest.mark.parametrize('system', ['Linux', 'Windows'])
def test_without_rights_rules_are_simulated(system, state, monkeypatch, client):
    monkeypatch.setattr(scanner, 'platform', type('P', (), {'system': staticmethod(lambda: system)}))
    monkeypatch.setattr(scanner, 'is_privileged', lambda: False)
    monkeypatch.setattr(scanner, '_run', lambda cmd: False)  # every OS command is refused
    deny = add(client, '10.0.0.0/24', 22)
    allow = add(client, '10.0.0.5', 22, 'allow')
    assert not deny['enforced'] and not allow['enforced']
    assert simulated('10.0.0.6', 22) and not simulated('10.0.0.5', 22)
    log = [e['msg'] for e in scanner.recent_audit]
    assert all('(simulation)' in m for m in log)
