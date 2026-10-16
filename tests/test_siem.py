"""SIEM events: every scan result, new open port and firewall rule change is written as an
Elastic Common Schema (ECS) event, one JSON object per line."""
import json
import os
import re
import time

import pytest

import app as scanner
from conftest import FakeFirewall


class FakeNmap:
    """Stands in for nmap.PortScanner. `hosts` maps ip -> {port: (state, service)}."""
    hosts = {}

    def scan(self, hosts, arguments):
        self.result = {ip: ports for ip, ports in FakeNmap.hosts.items() if ip in hosts.split()}

    def all_hosts(self):
        return list(self.result)

    def __getitem__(self, ip):
        ports = self.result[ip]
        table = {p: {'state': state, 'name': service, 'product': '', 'version': ''} for p, (state, service) in ports.items()}

        class Host(dict):
            def all_protocols(self):
                return ['tcp']
        return Host(tcp=table)


@pytest.fixture
def nmap_fake(monkeypatch):
    monkeypatch.setattr(scanner.nmap, 'PortScanner', FakeNmap)
    return FakeNmap


def scan(target, hosts=None):
    """Run one scan the way the page does, but synchronously."""
    if hosts is not None:
        FakeNmap.hosts = hosts
    sid = 'test-sid'
    scanner.active_scans[sid] = {'cancel': False}
    scanner.run_scan(sid, target, '-sS', scanner.plan_chunks(target))


def events(action=None):
    path = scanner.siem_path()
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
    return [e for e in rows if action is None or e['event']['action'] == action]


ISO = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')


def assert_ecs(e):
    """The fields every SIEM needs to place and filter the event."""
    assert ISO.match(e['@timestamp'])
    assert e['ecs']['version'] == scanner.ECS_VERSION
    ev = e['event']
    assert ev['module'] == 'netscan' and ev['dataset'] in ('netscan.scan', 'netscan.firewall')
    assert ev['kind'] in ('event', 'alert')
    assert isinstance(ev['category'], list) and isinstance(ev['type'], list)
    assert ev['action'] and e['message']
    assert e['observer']['type'] == 'scanner' and e['observer']['hostname']


# ---------- scans ----------

def test_scan_writes_start_port_and_completion_events(state, nmap_fake):
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh'), 80: ('filtered', 'http')}})
    all_events = events()
    assert [e['event']['action'] for e in all_events] == ['scan-started', 'port-state', 'port-state', 'scan-completed']
    for e in all_events:
        assert_ecs(e)
    ssh = next(e for e in events('port-state') if e['destination']['port'] == 22)
    assert ssh['destination']['ip'] == '10.0.0.5'
    assert ssh['network']['transport'] == 'tcp'
    assert ssh['service']['name'] == 'ssh'
    assert ssh['netscan']['port'] == {'state': 'open', 'blocked_by_rule': False}
    done = events('scan-completed')[0]
    assert done['event']['outcome'] == 'success'
    assert done['netscan']['scan']['open'] == 1 and done['netscan']['scan']['filtered'] == 1
    assert done['event']['duration'] >= 0 and ISO.match(done['event']['start'])
    # all events of one scan share its id
    assert len({e['netscan']['scan']['id'] for e in all_events}) == 1


def test_new_open_port_is_an_alert(state, nmap_fake):
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh')}})
    assert events('new-open-port') == []  # nothing to compare the first scan with
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh'), 4444: ('open', 'krb524')}})
    [alert] = events('new-open-port')
    assert_ecs(alert)
    assert alert['event']['kind'] == 'alert' and alert['event']['severity'] == 7
    assert alert['destination'] == {'ip': '10.0.0.5', 'address': '10.0.0.5', 'port': 4444}
    assert ISO.match(alert['netscan']['scan']['previous_scan'])


def test_closed_port_since_last_scan_is_reported(state, nmap_fake):
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh'), 80: ('open', 'http')}})
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh')}})
    [gone] = events('port-no-longer-open')
    assert gone['destination']['port'] == 80 and gone['event']['kind'] == 'event'


def test_ports_blocked_by_a_rule_are_marked(firewall, client, nmap_fake):
    client.emit('add_firewall_rule', {'ip': '10.0.0.0/24', 'port': '22', 'action': 'deny', 'proto': 'tcp', 'duration': ''})
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh'), 80: ('open', 'http')}})
    by_port = {e['destination']['port']: e for e in events('port-state')}
    assert by_port[22]['netscan']['port']['blocked_by_rule'] is True
    assert by_port[80]['netscan']['port']['blocked_by_rule'] is False
    assert events('scan-completed')[0]['netscan']['scan']['blocked_by_rule'] == 1


def test_failed_scan_is_reported(state, monkeypatch):
    class Broken:
        def scan(self, hosts, arguments):
            raise scanner.nmap.PortScannerError('You requested a scan type which requires root privileges.')
    monkeypatch.setattr(scanner.nmap, 'PortScanner', Broken)
    scan('10.0.0.5')
    [failed] = events('scan-failed')
    assert_ecs(failed)
    assert failed['event']['outcome'] == 'failure'
    assert 'root privileges' in failed['error']['message']


def test_ipv6_ports_keep_the_whole_address():
    assert scanner.split_port_key('2001:db8::5:443/tcp') == ('2001:db8::5', 443, 'tcp')


# ---------- firewall rules ----------

def test_rule_changes_are_configuration_events(firewall, client):
    client.emit('add_firewall_rule', {'ip': '10.0.0.0/24', 'port': '8000-8100', 'action': 'deny', 'proto': 'tcp', 'duration': ''})
    client.emit('add_firewall_rule', {'ip': '10.0.0.5', 'port': '8080', 'action': 'allow', 'proto': 'tcp', 'duration': ''})
    deny, allow = events('firewall-rule-added')
    for e in (deny, allow):
        assert_ecs(e)
        assert e['event']['dataset'] == 'netscan.firewall'
        assert e['event']['category'] == ['configuration', 'network'] and e['event']['type'] == ['creation']
        assert e['event']['outcome'] == 'success' and e['netscan']['rule']['mode'] == 'enforced'
        assert e['rule']['ruleset'] == {'Linux': 'iptables', 'Windows': 'windows-firewall'}[firewall.system]
        assert e['netscan']['rule']['command']  # the exact OS command, for the analyst
    # a range has no single IP or port, so only .address is set for it
    assert deny['source'] == {'address': '10.0.0.0/24'} and 'port' not in deny['destination']
    assert allow['source'] == {'ip': '10.0.0.5', 'address': '10.0.0.5'} and allow['destination']['port'] == 8080
    # an allow rule opens traffic, so it is rated higher than a block
    assert allow['event']['severity'] > deny['event']['severity']

    client.emit('remove_firewall_rule', {'rule_id': allow['rule']['id']})
    [removed] = events('firewall-rule-removed')
    assert removed['event']['type'] == ['deletion'] and removed['rule']['id'] == allow['rule']['id']


def test_expired_rule_is_reported(firewall, client, monkeypatch):
    client.emit('add_firewall_rule', {'ip': '10.0.0.5', 'port': '22', 'action': 'deny', 'proto': 'tcp', 'duration': 60})
    monkeypatch.setattr(scanner.time, 'time', lambda: 4102444800)
    scanner.expire_due_rules()
    [expired] = events('firewall-rule-expired')
    assert expired['event']['type'] == ['deletion'] and expired['netscan']['rule']['expires_at']


def test_rule_without_rights_is_marked_simulated(state, monkeypatch, client):
    monkeypatch.setattr(scanner, 'is_privileged', lambda: False)
    monkeypatch.setattr(scanner, '_run', lambda cmd: False)
    client.emit('add_firewall_rule', {'ip': '10.0.0.5', 'port': '22', 'action': 'deny', 'proto': 'tcp', 'duration': ''})
    [e] = events('firewall-rule-added')
    assert e['event']['outcome'] == 'unknown' and e['netscan']['rule']['mode'] == 'simulated'
    assert e['rule']['ruleset'] == 'simulation'


def test_failed_firewall_command_is_a_failure(state, monkeypatch, client):
    monkeypatch.setattr(scanner, 'platform', type('P', (), {'system': staticmethod(lambda: 'Linux')}))
    monkeypatch.setattr(scanner, 'is_privileged', lambda: True)
    monkeypatch.setattr(scanner, '_run', lambda cmd: False)  # e.g. iptables missing
    client.emit('add_firewall_rule', {'ip': '10.0.0.5', 'port': '22', 'action': 'deny', 'proto': 'tcp', 'duration': ''})
    [e] = events('firewall-rule-added')
    assert e['event']['outcome'] == 'failure' and e['netscan']['rule']['mode'] == 'failed'
    assert e['event']['severity'] == 6


# ---------- settings ----------

def test_siem_log_can_be_turned_off(state, nmap_fake, monkeypatch):
    monkeypatch.setenv('NETSCAN_SIEM_LOG', 'off')
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh')}})
    assert scanner.siem_path() is None
    assert not scanner.SIEM_FILE.exists()


def test_siem_log_path_can_be_changed(state, nmap_fake, monkeypatch, tmp_path):
    target = tmp_path / 'elsewhere' / 'events.ndjson'
    monkeypatch.setenv('NETSCAN_SIEM_LOG', str(target))
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh')}})
    assert target.exists() and len(target.read_text().splitlines()) == 3


# ---------- sample session for the Wazuh rule test in CI ----------

@pytest.mark.skipif(not os.environ.get('SIEM_SAMPLE_OUT'), reason='set SIEM_SAMPLE_OUT=path to write a sample session')
def test_write_sample_session(firewall, client, nmap_fake, monkeypatch):
    """A realistic session written with the app's own code, which CI feeds to a real Wazuh manager."""
    out = os.environ['SIEM_SAMPLE_OUT']
    monkeypatch.setenv('NETSCAN_SIEM_LOG', out)
    if os.path.exists(out):
        os.remove(out)
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh'), 80: ('open', 'http')}})
    client.emit('add_firewall_rule', {'ip': '10.0.0.0/24', 'port': '8000-8100', 'action': 'deny', 'proto': 'tcp', 'duration': ''})
    client.emit('add_firewall_rule', {'ip': '10.0.0.5', 'port': '8080', 'action': 'allow', 'proto': 'tcp', 'duration': 60})
    allow_id = events('firewall-rule-added')[-1]['rule']['id']
    client.emit('remove_firewall_rule', {'rule_id': allow_id})
    client.emit('add_firewall_rule', {'ip': '10.0.0.9', 'port': '3389', 'action': 'deny', 'proto': 'tcp', 'duration': 60})
    real_time = time.time
    monkeypatch.setattr(scanner.time, 'time', lambda: real_time() + 120)
    scanner.expire_due_rules()
    monkeypatch.setattr(scanner.time, 'time', real_time)
    # six new services appear at once, then one goes away
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh'), 80: ('open', 'http'), 4444: ('open', 'krb524'),
                                   5555: ('open', 'freeciv'), 6666: ('open', 'irc'), 7777: ('open', 'cbt'),
                                   8888: ('open', 'sun-answerbook'), 9999: ('open', 'abyss')}})
    scan('10.0.0.5', {'10.0.0.5': {22: ('open', 'ssh'), 4444: ('open', 'krb524'), 5555: ('open', 'freeciv'),
                                   6666: ('open', 'irc'), 7777: ('open', 'cbt'), 8888: ('open', 'sun-answerbook'),
                                   9999: ('open', 'abyss')}})
    monkeypatch.setattr(scanner, '_run', lambda cmd: False)  # the OS firewall refuses the next rule
    client.emit('add_firewall_rule', {'ip': '10.0.0.7', 'port': '22', 'action': 'deny', 'proto': 'tcp', 'duration': ''})

    class Broken:
        def scan(self, hosts, arguments):
            raise scanner.nmap.PortScannerError('nmap: Failed to resolve "nosuchhost.invalid".')
    monkeypatch.setattr(scanner.nmap, 'PortScanner', Broken)
    scan('10.0.0.6')
    assert len(events('new-open-port')) == 6
