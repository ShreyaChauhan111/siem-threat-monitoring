"""Detection rules. Each rule is stateful and processes events in time order.

Every rule maps to a MITRE ATT&CK technique. Add a new rule by subclassing Rule,
implementing process(ev), and appending the class to ALL_RULES.
"""
import base64
import os
import re
import statistics
from collections import defaultdict, deque

from .enrich import is_internal


def _prune(dq, now, window, key=lambda x: x):
    while dq and (now - key(dq[0])).total_seconds() > window:
        dq.popleft()


class Rule:
    id = "R000"
    name = "Base rule"
    severity = "low"
    mitre = ""

    def __init__(self, cfg=None, base_dir="."):
        self.cfg = cfg or {}
        self.base_dir = base_dir

    def alert(self, ev, description, key, severity=None):
        return {"rule_id": self.id, "name": self.name, "severity": severity or self.severity,
                "mitre": self.mitre, "ts": ev["ts"], "host": ev.get("host"),
                "user": ev.get("user"), "src_ip": ev.get("src_ip"),
                "description": description, "key": key}

    def process(self, ev):
        return []


class BruteForce(Rule):
    id, name, severity = "R001", "Brute-force login attempts", "high"
    mitre = "T1110.001 Credential Access"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.fails = defaultdict(deque)

    def process(self, ev):
        if ev["event_type"] != "logon" or ev["outcome"] != "failure" or not ev["src_ip"]:
            return []
        dq = self.fails[(ev["src_ip"], ev["user"])]
        dq.append(ev["ts"])
        _prune(dq, ev["ts"], self.cfg.get("window_seconds", 120))
        if len(dq) >= self.cfg.get("threshold", 5):
            return [self.alert(ev, f"{len(dq)} failed logins for '{ev['user']}' from {ev['src_ip']} "
                                   f"({ev['country']}) within {self.cfg.get('window_seconds', 120)}s",
                               key=ev["src_ip"])]
        return []


class PasswordSpray(Rule):
    id, name, severity = "R002", "Password spraying", "high"
    mitre = "T1110.003 Credential Access"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.fails = defaultdict(deque)

    def process(self, ev):
        if ev["event_type"] != "logon" or ev["outcome"] != "failure" or not ev["src_ip"]:
            return []
        dq = self.fails[ev["src_ip"]]
        dq.append((ev["ts"], ev["user"]))
        _prune(dq, ev["ts"], self.cfg.get("window_seconds", 300), key=lambda x: x[0])
        users = {u for _, u in dq}
        if len(users) >= self.cfg.get("threshold", 8):
            return [self.alert(ev, f"{len(users)} distinct accounts failed from {ev['src_ip']} "
                                   f"({ev['country']}) within {self.cfg.get('window_seconds', 300)}s",
                               key=ev["src_ip"])]
        return []


class SuccessAfterFailures(Rule):
    id, name, severity = "R003", "Successful login after repeated failures", "critical"
    mitre = "T1078 Initial Access"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.fails = defaultdict(deque)

    def process(self, ev):
        if ev["event_type"] != "logon" or not ev["src_ip"]:
            return []
        dq = self.fails[ev["src_ip"]]
        _prune(dq, ev["ts"], self.cfg.get("window_seconds", 600))
        if ev["outcome"] == "failure":
            dq.append(ev["ts"])
        elif len(dq) >= self.cfg.get("threshold", 5):
            return [self.alert(ev, f"Account '{ev['user']}' logged in from {ev['src_ip']} after "
                                   f"{len(dq)} recent failures: possible compromise", key=ev["src_ip"])]
        return []


class ImpossibleTravel(Rule):
    id, name, severity = "R004", "Impossible travel", "high"
    mitre = "T1078 Initial Access"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.last = {}

    def process(self, ev):
        if ev["event_type"] != "logon" or ev["outcome"] != "success":
            return []
        cc = ev["country"]
        if cc in (None, "INTERNAL", "??"):
            return []
        prev = self.last.get(ev["user"])
        self.last[ev["user"]] = (ev["ts"], cc, ev["src_ip"])
        if prev and prev[1] != cc and (ev["ts"] - prev[0]).total_seconds() <= self.cfg.get("window_seconds", 3600):
            mins = int((ev["ts"] - prev[0]).total_seconds() // 60)
            return [self.alert(ev, f"'{ev['user']}' logged in from {prev[1]} ({prev[2]}) then {cc} "
                                   f"({ev['src_ip']}) {mins} min later", key=ev["user"])]
        return []


class EncodedPowerShell(Rule):
    id, name, severity = "R005", "Suspicious PowerShell execution", "high"
    mitre = "T1059.001 Execution"
    INDICATORS = ("-enc", "-encodedcommand", "downloadstring", "iex(", "invoke-expression", "-w hidden")

    def process(self, ev):
        if ev["event_type"] != "process_create" or not ev["cmdline"]:
            return []
        cmd = ev["cmdline"].lower()
        if "powershell" not in cmd or not any(i in cmd for i in self.INDICATORS):
            return []
        decoded = ""
        m = re.search(r"-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]{16,})", ev["cmdline"], re.I)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-16le", "replace")[:160]
            except Exception:
                decoded = "(could not decode)"
        desc = f"Suspicious PowerShell on {ev['host']} by '{ev['user']}'"
        if decoded:
            desc += f"; decoded payload: {decoded}"
        return [self.alert(ev, desc, key=(ev["host"], ev["user"]))]


class LogCleared(Rule):
    id, name, severity = "R006", "Audit log cleared", "critical"
    mitre = "T1070.001 Defense Evasion"

    def process(self, ev):
        if ev["event_type"] == "log_cleared":
            return [self.alert(ev, f"Security log cleared on {ev['host']} by '{ev['user']}'", key=ev["host"])]
        return []


class PrivilegedGroupAdd(Rule):
    id, name, severity = "R007", "Privileged group modified", "high"
    mitre = "T1098 Persistence"

    def process(self, ev):
        groups = [g.lower() for g in self.cfg.get("groups", ["Domain Admins"])]
        if ev["event_type"] == "group_add" and (ev["group"] or "").lower() in groups:
            return [self.alert(ev, f"'{ev['process']}' added to '{ev['group']}' by '{ev['user']}' on {ev['host']}",
                               key=(ev["group"], ev["process"]))]
        return []


class DNSBeaconing(Rule):
    id, name, severity = "R008", "DNS beaconing (regular intervals)", "medium"
    mitre = "T1071.004 Command and Control"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.seen = defaultdict(lambda: deque(maxlen=30))

    def process(self, ev):
        if ev["event_type"] != "dns" or not ev["domain"]:
            return []
        if any(ev["domain"].endswith(a) for a in self.cfg.get("allowlist", [])):
            return []
        dq = self.seen[(ev["host"], ev["domain"])]
        dq.append(ev["ts"])
        if len(dq) < self.cfg.get("min_queries", 10):
            return []
        times = list(dq)
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean >= 1 and statistics.pstdev(gaps) / mean <= self.cfg.get("max_cv", 0.1):
            return [self.alert(ev, f"{ev['host']} queried '{ev['domain']}' {len(dq)} times at a steady "
                                   f"~{mean:.0f}s interval", key=(ev["host"], ev["domain"]))]
        return []


class Exfiltration(Rule):
    id, name, severity = "R009", "Large outbound data transfer", "high"
    mitre = "T1041 Exfiltration"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.flows = defaultdict(deque)

    def process(self, ev):
        if ev["event_type"] != "network" or not ev["bytes_out"] or is_internal(ev["dst_ip"]):
            return []
        dq = self.flows[ev["src_ip"]]
        dq.append((ev["ts"], ev["bytes_out"]))
        _prune(dq, ev["ts"], self.cfg.get("window_seconds", 600), key=lambda x: x[0])
        total = sum(b for _, b in dq)
        if total >= self.cfg.get("bytes_threshold", 100_000_000):
            return [self.alert(ev, f"{ev['src_ip']} sent {total / 1e6:.0f} MB to external hosts "
                                   f"(latest: {ev['dst_ip']}) within {self.cfg.get('window_seconds', 600)}s",
                               key=ev["src_ip"])]
        return []


class ThreatIntelMatch(Rule):
    id, name, severity = "R010", "Threat-intel IP match", "high"
    mitre = "T1071 Command and Control"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.ips = set()
        path = os.path.join(self.base_dir, self.cfg.get("blocklist_file", "data/blocklist.txt"))
        if os.path.exists(path):
            with open(path) as f:
                self.ips = {l.strip() for l in f if l.strip() and not l.startswith("#")}

    def process(self, ev):
        for field in ("dst_ip", "src_ip"):
            ip = ev.get(field)
            if ip and ip in self.ips:
                return [self.alert(ev, f"Traffic involving blocklisted IP {ip} ({field}) on {ev['host']}", key=ip)]
        return []


ALL_RULES = [BruteForce, PasswordSpray, SuccessAfterFailures, ImpossibleTravel, EncodedPowerShell,
             LogCleared, PrivilegedGroupAdd, DNSBeaconing, Exfiltration, ThreatIntelMatch]
