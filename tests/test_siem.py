import json
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from siem import engine, generator, parser  # noqa: E402

with open(os.path.join(BASE, "config.json")) as f:
    CFG = json.load(f)


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        generator.generate(cls.tmp)
        cls.events = parser.parse_dir(cls.tmp)
        cls.alerts = engine.analyze(cls.events, CFG, BASE)
        cls.ids = {a["rule_id"] for a in cls.alerts}

    def test_parsed_all_sources(self):
        self.assertEqual({e["source"] for e in self.events}, {"linux-auth", "windows", "firewall", "dns"})

    def test_all_ten_rules_fire(self):
        self.assertEqual(self.ids, {f"R{n:03d}" for n in range(1, 11)})

    def test_no_false_positive_on_benign_users(self):
        # benign noise must not trigger brute force from internal addresses
        for a in self.alerts:
            if a["rule_id"] in ("R001", "R002", "R003"):
                self.assertFalse(a["src_ip"].startswith("10."), a)

    def test_alerts_deduplicated(self):
        # one brute-force campaign -> exactly one alert despite many failures
        self.assertEqual(len([a for a in self.alerts if a["rule_id"] == "R001"]), 1)

    def test_powershell_payload_decoded(self):
        ps = [a for a in self.alerts if a["rule_id"] == "R005"][0]
        self.assertIn("DownloadString", ps["description"])


if __name__ == "__main__":
    unittest.main()
