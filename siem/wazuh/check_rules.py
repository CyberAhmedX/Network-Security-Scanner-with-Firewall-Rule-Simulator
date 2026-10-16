"""Feed scanner events to a running Wazuh manager's wazuh-logtest and check which rule each one hits.

Usage: python siem/wazuh/check_rules.py <container> <events.ndjson> [--expect-correlation]
CI runs it against the official wazuh/wazuh-manager image with netscan_rules.xml loaded.
"""
import json
import re
import subprocess
import sys


def expected_rules(event):
    """The rule IDs an event may hit, from what netscan_rules.xml promises."""
    action = event['event']['action']
    if event['event']['dataset'] == 'netscan.firewall' and event['event'].get('outcome') == 'failure':
        return {'100506'}
    if action == 'firewall-rule-added':
        return {'100507'} if event['netscan']['rule']['action'] == 'deny' else {'100508'}
    return {
        'scan-completed': {'100501'},
        'scan-failed': {'100502'},
        'new-open-port': {'100503', '100505'},  # 100505 once 5 have been seen within 10 minutes
        'port-no-longer-open': {'100504'},
        'firewall-rule-removed': {'100509'},
        'firewall-rule-expired': {'100510'},
        'firewall-rule-restored': {'100511'},
    }.get(action, {'100500'})  # scan-started, scan-stopped, port-state: archived, no alert


def main():
    container, path = sys.argv[1], sys.argv[2]
    lines = [l for l in open(path, encoding='utf-8').read().splitlines() if l.strip()]
    run = subprocess.run(['docker', 'exec', '-i', container, '/var/ossec/bin/wazuh-logtest'],
                         input='\n'.join(lines) + '\n', capture_output=True, text=True, timeout=300)
    blocks = run.stdout.split('**Phase 1: Completed pre-decoding.')[1:]
    results = {}
    for block in blocks:
        full = re.search(r"\tfull event: '(.*)'\n", block)
        if not full:
            continue
        try:
            event = json.loads(full.group(1))
        except ValueError:
            continue
        key = (event['@timestamp'], event['event']['action'], event['message'])
        results.setdefault(key, []).append(block)

    failures, seen = [], set()
    for line in lines:
        event = json.loads(line)
        key = (event['@timestamp'], event['event']['action'], event['message'])
        found = results.get(key)
        if not found:
            failures.append((event['event']['action'], sorted(expected_rules(event)), None, 'no result from wazuh-logtest'))
            print(f"FAIL {event['event']['action']:<22} no result  {event['message'][:70]}")
            continue
        block = found.pop(0)
        decoder = re.search(r"\tname: '([^']+)'", block)
        rule = re.search(r"\tid: '(\d+)'", block)
        level = re.search(r"\tlevel: '(\d+)'", block)
        got = rule.group(1) if rule else None
        seen.add(got)
        want = expected_rules(event)
        ok = bool(decoder) and decoder.group(1) == 'json' and got in want
        print(f"{'ok  ' if ok else 'FAIL'} {event['event']['action']:<22} rule {got} level {level.group(1) if level else '-'}"
              f"  {event['message'][:70]}")
        if not ok:
            failures.append((event['event']['action'], sorted(want), got, block.strip()[:1500]))

    if '--expect-correlation' in sys.argv and '100505' not in seen:
        failures.append(('correlation', ['100505'], None, 'the burst of new open ports did not trigger 100505'))
    for action, want, got, detail in failures:
        print(f'\n--- {action}: expected {want}, got {got}\n{detail}')
    print(f"\n{len(lines)} events, {len(blocks)} wazuh-logtest results, {len(failures)} failures")
    if failures and not blocks:
        print(run.stdout[-3000:], run.stderr[-2000:])
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
