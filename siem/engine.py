"""Detection engine: runs every enabled rule over time-ordered events with alert de-duplication."""
from .rules import ALL_RULES


def build_rules(config, base_dir="."):
    rules = []
    for cls in ALL_RULES:
        rcfg = config.get("rules", {}).get(cls.id, {})
        if rcfg.get("enabled", True):
            rules.append(cls(rcfg, base_dir))
    return rules


def analyze(events, config, base_dir="."):
    rules = build_rules(config, base_dir)
    cooldown = config.get("cooldown_seconds", 600)
    last = {}
    alerts = []
    for ev in sorted(events, key=lambda e: e["ts"]):
        for rule in rules:
            for a in rule.process(ev):
                k = (a["rule_id"], a.pop("key"))
                if k in last and (a["ts"] - last[k]).total_seconds() < cooldown:
                    continue
                last[k] = a["ts"]
                alerts.append(a)
    return alerts
