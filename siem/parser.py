"""Parsers: raw log lines -> normalized event dicts.

Normalized fields: ts, source, host, event_type, outcome, user, src_ip, dst_ip,
country, process, cmdline, bytes_out, domain, group, raw.
Event types: logon, process_create, log_cleared, group_add, network, dns.
"""
import json
import os
import re
from datetime import datetime, timezone

from .enrich import country_of


def _ts(s):
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def _event(**kw):
    base = dict(ts=None, source=None, host=None, event_type=None, outcome=None,
                user=None, src_ip=None, dst_ip=None, country=None, process=None,
                cmdline=None, bytes_out=0, domain=None, group=None, raw="")
    base.update(kw)
    ip = base["src_ip"] if base["event_type"] == "logon" else base["dst_ip"]
    base["country"] = country_of(ip)
    return base


# ---------- Linux sshd (syslog RFC3339) ----------
SSH_LINE = re.compile(r"^(?P<ts>\S+) (?P<host>\S+) sshd\[\d+\]: (?P<msg>.*)$")
SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port")
SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port")


def parse_auth(line):
    m = SSH_LINE.match(line)
    if not m:
        return None
    msg = m["msg"]
    for rx, outcome in ((SSH_FAIL, "failure"), (SSH_OK, "success")):
        mm = rx.search(msg)
        if mm:
            return _event(ts=_ts(m["ts"]), source="linux-auth", host=m["host"],
                          event_type="logon", outcome=outcome, user=mm["user"],
                          src_ip=mm["ip"], raw=line)
    return None


# ---------- Windows Security events (JSON lines, e.g. from winlogbeat/Wazuh) ----------
def parse_windows(line):
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    eid = int(d.get("EventID", 0))
    common = dict(ts=_ts(d["TimeCreated"]), source="windows", host=d.get("Computer"), raw=line)
    if eid in (4624, 4625):
        return _event(event_type="logon", outcome="success" if eid == 4624 else "failure",
                      user=d.get("TargetUserName"), src_ip=d.get("IpAddress"), **common)
    if eid == 4688:
        return _event(event_type="process_create", outcome="success",
                      user=d.get("SubjectUserName"), process=d.get("NewProcessName"),
                      cmdline=d.get("CommandLine"), **common)
    if eid == 1102:
        return _event(event_type="log_cleared", outcome="success",
                      user=d.get("SubjectUserName"), **common)
    if eid in (4728, 4732):
        return _event(event_type="group_add", outcome="success",
                      user=d.get("SubjectUserName"), group=d.get("TargetUserName"),
                      process=d.get("MemberName"), **common)
    return None


# ---------- Firewall / DNS key=value ----------
KV = re.compile(r"(\w+)=(\S+)")


def parse_firewall(line):
    parts = line.split(" ", 2)
    if len(parts) < 3:
        return None
    kv = dict(KV.findall(parts[2]))
    if "src" not in kv or "dst" not in kv:
        return None
    return _event(ts=_ts(parts[0]), source="firewall", host=parts[1], event_type="network",
                  outcome=kv.get("action"), src_ip=kv["src"], dst_ip=kv["dst"],
                  bytes_out=int(kv.get("bytes_out", 0)), raw=line)


def parse_dns(line):
    parts = line.split(" ", 1)
    if len(parts) < 2:
        return None
    kv = dict(KV.findall(parts[1]))
    if "query" not in kv:
        return None
    return _event(ts=_ts(parts[0]), source="dns", host=kv.get("host"), event_type="dns",
                  outcome="success", domain=kv["query"].lower(), raw=line)


PARSERS = {"auth": parse_auth, "windows": parse_windows,
           "firewall": parse_firewall, "dns": parse_dns}


def parse_file(path):
    kind = os.path.basename(path).split(".")[0].split("-")[0]
    fn = PARSERS.get(kind)
    if not fn:
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                ev = fn(line)
                if ev:
                    out.append(ev)
    return out


def parse_dir(directory):
    events = []
    for name in sorted(os.listdir(directory)):
        events.extend(parse_file(os.path.join(directory, name)))
    events.sort(key=lambda e: e["ts"])
    return events
