"""Zero-dependency web dashboard (http.server) backed by the SQLite store."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import storage

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Mini SIEM Dashboard</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--line:#334155;
--critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#3b82f6}
@media (prefers-color-scheme: light){:root{--bg:#f1f5f9;--card:#fff;--text:#0f172a;--muted:#64748b;--line:#e2e8f0}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--text)}
header{padding:16px 24px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
h1{font-size:18px;margin:0}main{padding:20px 24px;max-width:1300px;margin:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.big{font-size:30px;font-weight:700}.muted{color:var(--muted);font-size:12px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}@media(max-width:800px){.two{grid-template-columns:1fr}}
.bar{display:flex;align-items:center;gap:8px;margin:6px 0}.bar span.l{width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar i{display:block;height:10px;border-radius:5px;background:var(--low)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}.wrap{overflow-x:auto}
.sev{padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium);color:#111}.sev.low{background:var(--low)}
select,input{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px 10px}
.row{display:flex;gap:10px;margin-bottom:10px;align-items:center;flex-wrap:wrap}
</style></head><body>
<header><h1>Mini SIEM &middot; Threat Monitoring</h1><span class="muted" id="upd"></span></header>
<main>
<div class="grid" id="kpis"></div>
<div class="two"><div class="card"><b>Top alerting source IPs</b><div id="ips"></div></div>
<div class="card"><b>Alerts by MITRE ATT&amp;CK technique</b><div id="mitre"></div></div></div>
<div class="card" style="margin-bottom:18px"><div class="row"><b>Alerts</b>
<select id="sev"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div>
<div class="wrap"><table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Rule</th><th>Host</th><th>User</th><th>Source IP</th><th>Details</th></tr></thead><tbody id="alerts"></tbody></table></div></div>
<div class="card"><div class="row"><b>Threat hunt: search events</b><input id="q" placeholder="user, IP, host, text..." size="30"></div>
<div class="wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Host</th><th>Type</th><th>Outcome</th><th>User</th><th>Src IP</th><th>Dst IP</th><th>Geo</th></tr></thead><tbody id="events"></tbody></table></div></div>
</main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const col={critical:"var(--critical)",high:"var(--high)",medium:"var(--medium)",low:"var(--low)"};
function bars(el,rows,k){const m=Math.max(1,...rows.map(r=>r.n));$(el).innerHTML=rows.map(r=>`<div class="bar"><span class="l">${esc(r[k])}</span><i style="width:${r.n/m*60}%"></i><b>${r.n}</b></div>`).join("")||'<div class="muted">No data</div>'}
async function load(){
 const s=await (await fetch("/api/stats")).json();
 const sev=Object.fromEntries(s.by_severity.map(r=>[r.severity,r.n]));
 $("kpis").innerHTML=`<div class="card"><div class="muted">Events ingested</div><div class="big">${s.total_events.toLocaleString()}</div></div>
 <div class="card"><div class="muted">Total alerts</div><div class="big">${s.total_alerts}</div></div>`+
 ["critical","high","medium","low"].map(k=>`<div class="card"><div class="muted">${k}</div><div class="big" style="color:${col[k]}">${sev[k]||0}</div></div>`).join("");
 bars("ips",s.top_ips,"src_ip");bars("mitre",s.by_mitre,"mitre");
 const a=await (await fetch("/api/alerts?severity="+$("sev").value)).json();
 $("alerts").innerHTML=a.map(r=>`<tr><td>${esc(r.ts.replace("T"," ").slice(0,19))}</td><td><span class="sev ${r.severity}">${r.severity}</span></td>
 <td><b>${esc(r.name)}</b><div class="muted">${esc(r.rule_id)} &middot; ${esc(r.mitre)}</div></td><td>${esc(r.host)}</td><td>${esc(r.user)}</td><td>${esc(r.src_ip)}</td><td>${esc(r.description)}</td></tr>`).join("");
 $("upd").textContent="Updated "+new Date().toLocaleTimeString();
}
async function hunt(){const e=await (await fetch("/api/events?q="+encodeURIComponent($("q").value))).json();
 $("events").innerHTML=e.map(r=>`<tr><td>${esc(r.ts.replace("T"," ").slice(0,19))}</td><td>${esc(r.source)}</td><td>${esc(r.host)}</td><td>${esc(r.event_type)}</td><td>${esc(r.outcome)}</td><td>${esc(r.user)}</td><td>${esc(r.src_ip)}</td><td>${esc(r.dst_ip)}</td><td>${esc(r.country)}</td></tr>`).join("")}
$("sev").onchange=load;let t;$("q").oninput=()=>{clearTimeout(t);t=setTimeout(hunt,250)};
load();hunt();setInterval(load,15000);
</script></body></html>"""


def make_handler(db_path):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, body, ctype="application/json", code=200):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            url = urlparse(self.path)
            qs = parse_qs(url.query)
            if url.path == "/":
                return self._send(PAGE, "text/html")
            conn = storage.connect(db_path)
            try:
                if url.path == "/api/stats":
                    return self._send(json.dumps(storage.stats(conn)))
                if url.path == "/api/alerts":
                    return self._send(json.dumps(storage.list_alerts(conn, qs.get("severity", [""])[0] or None)))
                if url.path == "/api/events":
                    return self._send(json.dumps(storage.search_events(conn, qs.get("q", [""])[0])))
            finally:
                conn.close()
            self._send(json.dumps({"error": "not found"}), code=404)

        def log_message(self, *a):
            pass
    return Handler


def serve(db_path, host="127.0.0.1", port=8080):
    srv = ThreadingHTTPServer((host, port), make_handler(db_path))
    print(f"Dashboard running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
