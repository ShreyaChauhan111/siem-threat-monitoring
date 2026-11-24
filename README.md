# Enterprise Threat Monitoring & SIEM Deployment: Working Project

A runnable, dependency-free mini SIEM that demonstrates the full pipeline from the project plan:
**collect -> parse/normalize -> enrich -> detect -> alert -> visualize -> hunt**.
It also includes configuration for deploying a production-grade SIEM (Wazuh) in `deploy/`.

## Quick start (2 minutes)

Requires only **Python 3.9+**. No `pip install` needed.

```bash
cd siem-project
python run.py demo            # generates logs, detects attacks, prints report, starts dashboard
# open http://127.0.0.1:8080
```

Windows: use `python run.py demo` (or `py run.py demo`) in PowerShell/CMD.

Run the tests: `python -m unittest discover -s tests -v`

Docker alternative: `docker compose up --build` then open http://localhost:8080.

## Commands

| Command | What it does |
|---|---|
| `python run.py demo` | Full demo: generate + ingest + report + dashboard |
| `python run.py generate` | Create simulated logs in `logs/` (benign noise + 8 attack scenarios) |
| `python run.py ingest` | Parse everything in `logs/`, run detections, store in SQLite |
| `python run.py report [--severity high]` | Print alerts in the terminal |
| `python run.py dashboard [--port 8080]` | Web dashboard with alert table, KPIs, MITRE view, event search |

## Project layout

```
run.py                 CLI entry point
config.json            Rule thresholds, enable/disable switches, paths
data/blocklist.txt     Threat-intel IP blocklist (edit freely)
siem/parser.py         Log parsers -> normalized events (sshd, Windows JSON, firewall, DNS)
siem/enrich.py         Internal-IP check + simulated GeoIP
siem/rules.py          10 detection rules mapped to MITRE ATT&CK
siem/engine.py         Runs rules with alert de-duplication/cooldown
siem/storage.py        SQLite storage and queries
siem/dashboard.py      Web UI + JSON API (/api/stats, /api/alerts, /api/events)
siem/generator.py      Realistic log + attack scenario generator
tests/test_siem.py     End-to-end tests (all 10 rules must fire)
deploy/                Real-world deployment: Wazuh quickstart, rsyslog forwarding, custom rules
```

## Detection rules

| ID | Detection | Severity | MITRE ATT&CK |
|---|---|---|---|
| R001 | Brute-force login attempts | High | T1110.001 |
| R002 | Password spraying | High | T1110.003 |
| R003 | Successful login after repeated failures | Critical | T1078 |
| R004 | Impossible travel | High | T1078 |
| R005 | Suspicious/encoded PowerShell (payload is decoded in the alert) | High | T1059.001 |
| R006 | Security audit log cleared | Critical | T1070.001 |
| R007 | Privileged group modification | High | T1098 |
| R008 | DNS beaconing (steady-interval queries) | Medium | T1071.004 |
| R009 | Large outbound data transfer | High | T1041 |
| R010 | Threat-intel IP match | High | T1071 |

Tune thresholds in `config.json`. To add a rule, subclass `Rule` in `siem/rules.py`, implement `process(ev)`, and append it to `ALL_RULES`.

## Simulated attack timeline (what the demo detects)

1. SSH brute force from `185.220.101.4`, then a successful login (R001, R003)
2. Password spray from `45.155.205.9` against the domain controller (R002)
3. Impossible travel for `alice`: India then Brazil in 15 minutes (R004)
4. DNS beaconing from `WS-014` to `cdn-update.badsite.xyz` every 30s (R008)
5. Encoded PowerShell download cradle on `WS-014` (R005)
6. `svc_backup2` added to Domain Admins (R007)
7. Security log cleared on `WS-014` (R006)
8. 150 MB sent from `WS-022` to a blocklisted IP (R009, R010)

## Using your own logs

Drop files into `logs/` named by type, then run `python run.py ingest`:

| File name | Format |
|---|---|
| `auth*.log` | Linux sshd lines in RFC3339 syslog format (`2026-11-17T10:00:00+00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2`) |
| `windows*.jsonl` | One JSON object per line with `TimeCreated`, `EventID`, `Computer`, plus event fields (4624, 4625, 4688, 1102, 4728/4732) |
| `firewall*.log` | `TIMESTAMP fw01 action=allow src=10.0.1.5 dst=8.8.8.8 dport=443 proto=tcp bytes_out=1234` |
| `dns*.log` | `TIMESTAMP host=WS-014 query=example.com type=A` |

To support another format, add a parser function in `siem/parser.py` and register it in `PARSERS`.

## Going to production

This mini SIEM is ideal for learning, demos, and prototyping detections. For a real enterprise deployment, follow `deploy/WAZUH_DEPLOYMENT.md` (agents, indexer cluster, dashboards, custom rules in `deploy/custom_wazuh_rules.xml`, log forwarding in `deploy/rsyslog-forward.conf`). The rules here map directly to Wazuh/Elastic/Splunk/Sentinel detections.

## Notes and limits

- GeoIP is a small simulated table. Use MaxMind GeoLite2 for real data.
- Processing is batch-based on files in `logs/`. A production SIEM streams events continuously.
- The dashboard binds to `127.0.0.1` with no authentication. Do not expose it publicly without a reverse proxy and authentication.
