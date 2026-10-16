# SIEM integration

The scanner writes every scan result, new open port and firewall rule change as an event in **Elastic Common Schema (ECS)**, one JSON object per line. Any SIEM that reads JSON lines can collect it. This folder has ready-made setups for **Wazuh** and **Elastic (Filebeat)**, and the Wazuh rules are tested against a real Wazuh manager on every push.

## Where the events go

- By default: `state/siem/netscan-events.ndjson`, next to `app.py`
- Somewhere else: start the scanner with `NETSCAN_SIEM_LOG=/var/log/netscan/events.ndjson`
- Turned off: `NETSCAN_SIEM_LOG=off`

## Events

Every event has `@timestamp`, `ecs.version`, `event.module: netscan`, `event.dataset`, `event.kind`, `event.category`, `event.type`, `event.action`, `message` and `observer` (the machine running the scanner). Events from one scan share `netscan.scan.id`.

**Scans** (`event.dataset: netscan.scan`)

- `scan-started` and `scan-completed`: target, Nmap arguments, counts of open, filtered and closed ports, ports blocked by a rule, and `event.duration`
- `scan-failed`: `event.outcome: failure` with Nmap's error in `error.message`
- `port-state`: one per reported port, with `destination.ip`, `destination.port`, `network.transport`, `service.name`, the Nmap state and whether a rule blocks it
- `new-open-port`: **an alert** (`event.kind: alert`, severity 7) for a port that is open now but wasn't in the previous scan of the same target and scan type
- `port-no-longer-open`: a port that was open in the previous scan and isn't now

**Firewall rules** (`event.dataset: netscan.firewall`)

- `firewall-rule-added`, `firewall-rule-removed`, `firewall-rule-expired`, `firewall-rule-restored`
- `netscan.rule.action` is `allow` or `deny`. An allow rule opens traffic, so it gets a higher severity than a deny rule.
- `netscan.rule.mode` says what really happened: `enforced` (the OS firewall has it, `event.outcome: success`), `simulated` (no admin/root rights, `unknown`) or `failed` (the OS firewall command failed, `failure`)
- `netscan.rule.command` is the exact `iptables` or `netsh` command that ran
- `source.ip` is set for a single address; ranges are in `source.address`

A real example from `samples/real-session.ndjson` (shortened): a scan of this machine on Linux after an allow rule was added inside a blocked range:

```json
{"@timestamp": "2026-10-16T19:33:19.523Z", "event": {"module": "netscan", "dataset": "netscan.scan", "kind": "event",
 "category": ["network"], "type": ["info"], "action": "port-state"},
 "message": "127.0.0.1:8081/tcp is filtered (blocked by a rule)",
 "destination": {"ip": "127.0.0.1", "address": "127.0.0.1", "port": 8081}, "network": {"transport": "tcp"},
 "service": {"name": "blackice-icecap"}, "netscan": {"port": {"state": "filtered", "blocked_by_rule": true}}}
```

## Wazuh

1. On the machine that runs the scanner, add the `<localfile>` block from `wazuh/ossec-localfile.xml` to the Wazuh agent's `ossec.conf`, change the path, and restart the agent.
2. On the Wazuh manager, copy `wazuh/netscan_rules.xml` to `/var/ossec/etc/rules/` and restart the manager.

Wazuh's built-in JSON decoder reads the events, and the rules match on the ECS fields:

- **100503, level 10:** new open port since the last scan
- **100505, level 12:** 5 or more new open ports on the same host within 10 minutes (correlation)
- **100506, level 10:** a firewall rule could not be applied to the OS firewall
- **100508, level 7:** allow rule added (traffic opened)
- **100507, level 5:** deny rule added
- **100502, level 5:** scan failed
- **100504, 100509:** port no longer open, rule removed (level 5)
- **100501, 100510, 100511:** scan completed, rule expired, rule restored (level 3)
- **100500, level 0:** every other scanner event, archived without an alert

**Tested:** GitHub Actions starts the official `wazuh/wazuh-manager` image with these rules, feeds it a full session written by the app's own code plus the real Linux session in `samples/`, and checks with `wazuh-logtest` that every event is decoded as JSON and hits the expected rule, including the correlation rule. See `wazuh/check_rules.py`.

## Elastic (Filebeat)

`elastic/filebeat.yml` reads the file with the `ndjson` parser. The events are already ECS, so no ingest pipeline is needed. Some KQL searches to start with:

- New exposure: `event.module : "netscan" and event.action : "new-open-port"`
- Traffic opened: `event.dataset : "netscan.firewall" and netscan.rule.action : "allow"`
- Rules the OS firewall refused: `event.dataset : "netscan.firewall" and event.outcome : "failure"`
- Ports a rule blocks: `event.action : "port-state" and netscan.port.blocked_by_rule : true`

## Splunk

Point a Universal Forwarder at the file with `sourcetype = _json`. Fields are extracted automatically, for example:

```
sourcetype=_json event.module=netscan event.action=new-open-port
| stats count by destination.ip, destination.port
```

The Elastic and Splunk setups are provided as starting points; only the Wazuh rules are tested automatically.
