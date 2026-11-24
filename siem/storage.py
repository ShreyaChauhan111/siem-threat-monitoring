"""SQLite storage for events and alerts."""
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts TEXT, source TEXT, host TEXT, event_type TEXT, outcome TEXT,
  user TEXT, src_ip TEXT, dst_ip TEXT, country TEXT, raw TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY, ts TEXT, rule_id TEXT, name TEXT, severity TEXT, mitre TEXT,
  host TEXT, user TEXT, src_ip TEXT, description TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""
SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


def connect(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def reset(conn):
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM alerts")
    conn.commit()


def insert_events(conn, events):
    conn.executemany(
        "INSERT INTO events(ts,source,host,event_type,outcome,user,src_ip,dst_ip,country,raw) VALUES(?,?,?,?,?,?,?,?,?,?)",
        [(e["ts"].isoformat(), e["source"], e["host"], e["event_type"], e["outcome"], e["user"],
          e["src_ip"], e["dst_ip"], e["country"], e["raw"]) for e in events])
    conn.commit()


def insert_alerts(conn, alerts):
    conn.executemany(
        "INSERT INTO alerts(ts,rule_id,name,severity,mitre,host,user,src_ip,description) VALUES(?,?,?,?,?,?,?,?,?)",
        [(a["ts"].isoformat(), a["rule_id"], a["name"], a["severity"], a["mitre"], a["host"],
          a["user"], a["src_ip"], a["description"]) for a in alerts])
    conn.commit()


def list_alerts(conn, severity=None, limit=500):
    q, args = "SELECT * FROM alerts", []
    if severity:
        q += " WHERE severity=?"
        args.append(severity)
    q += f" ORDER BY {SEV_ORDER}, ts DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in conn.execute(q, args)]


def search_events(conn, text="", limit=200):
    like = f"%{text}%"
    rows = conn.execute(
        "SELECT ts,source,host,event_type,outcome,user,src_ip,dst_ip,country FROM events "
        "WHERE raw LIKE ? OR user LIKE ? OR src_ip LIKE ? OR host LIKE ? ORDER BY ts DESC LIMIT ?",
        (like, like, like, like, limit))
    return [dict(r) for r in rows]


def stats(conn):
    def rows(q):
        return [dict(r) for r in conn.execute(q)]
    return {
        "total_events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "total_alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "by_severity": rows(f"SELECT severity, COUNT(*) n FROM alerts GROUP BY severity ORDER BY {SEV_ORDER}"),
        "by_source": rows("SELECT source, COUNT(*) n FROM events GROUP BY source ORDER BY n DESC"),
        "top_ips": rows("SELECT src_ip, COUNT(*) n FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT 8"),
        "by_mitre": rows("SELECT mitre, COUNT(*) n FROM alerts GROUP BY mitre ORDER BY n DESC"),
    }
