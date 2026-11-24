#!/usr/bin/env python3
"""Mini SIEM command line.

  python run.py demo        generate sample logs, ingest, detect, open dashboard
  python run.py generate    create simulated logs in ./logs
  python run.py ingest      parse ./logs, run detections, store results
  python run.py report      print alerts to the terminal
  python run.py dashboard   start the web dashboard
"""
import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from siem import dashboard, engine, generator, parser, storage  # noqa: E402

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[34m"}


def load_config(path):
    with open(path) as f:
        cfg = json.load(f)
    for k in ("log_dir", "db_path"):
        if not os.path.isabs(cfg[k]):
            cfg[k] = os.path.join(BASE, cfg[k])
    return cfg


def cmd_generate(cfg, args):
    counts = generator.generate(cfg["log_dir"], seed=args.seed)
    print(f"Generated logs in {cfg['log_dir']}: {counts}")


def cmd_ingest(cfg, args):
    events = parser.parse_dir(cfg["log_dir"])
    alerts = engine.analyze(events, cfg, BASE)
    conn = storage.connect(cfg["db_path"])
    storage.reset(conn)
    storage.insert_events(conn, events)
    storage.insert_alerts(conn, alerts)
    conn.close()
    print(f"Ingested {len(events)} events -> {len(alerts)} alerts stored in {cfg['db_path']}")


def cmd_report(cfg, args):
    conn = storage.connect(cfg["db_path"])
    alerts = storage.list_alerts(conn, args.severity)
    s = storage.stats(conn)
    conn.close()
    print(f"\n=== ALERT REPORT: {s['total_alerts']} alerts from {s['total_events']} events ===\n")
    for a in alerts:
        c = COLORS.get(a["severity"], "")
        print(f"{c}[{a['severity'].upper():8}]\033[0m {a['ts'][:19]}  {a['rule_id']}  {a['name']}")
        print(f"            {a['mitre']}\n            {a['description']}\n")


def cmd_dashboard(cfg, args):
    dashboard.serve(cfg["db_path"], args.host, args.port)


def cmd_demo(cfg, args):
    cmd_generate(cfg, args)
    cmd_ingest(cfg, args)
    args.severity = None
    cmd_report(cfg, args)
    if not args.no_dashboard:
        cmd_dashboard(cfg, args)


def main():
    p = argparse.ArgumentParser(description="Mini SIEM")
    p.add_argument("command", choices=["demo", "generate", "ingest", "report", "dashboard"])
    p.add_argument("--config", default=os.path.join(BASE, "config.json"))
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--no-dashboard", action="store_true")
    args = p.parse_args()
    cfg = load_config(args.config)
    {"demo": cmd_demo, "generate": cmd_generate, "ingest": cmd_ingest,
     "report": cmd_report, "dashboard": cmd_dashboard}[args.command](cfg, args)


if __name__ == "__main__":
    main()
