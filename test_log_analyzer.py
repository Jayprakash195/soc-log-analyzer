"""Unit tests for log_analyzer.py. Run: python3 -m unittest -v"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta

from log_analyzer import Event, analyze, max_in_window, parse_file, parse_line

YEAR = 2026
BASE = datetime(2026, 10, 27, 3, 0, 0)


def failed(sec, user, ip):
    return Event(BASE + timedelta(seconds=sec), "failed", user, ip, "password")


def accepted(sec, user, ip):
    return Event(BASE + timedelta(seconds=sec), "accepted", user, ip, "password")


class TestParser(unittest.TestCase):
    def test_01_parse_failed_line(self):
        line = ("Oct 27 03:14:22 srv sshd[1]: Failed password for invalid user "
                "admin from 203.0.113.5 port 4444 ssh2")
        ev = parse_line(line, YEAR)
        self.assertEqual((ev.kind, ev.user, ev.ip, ev.method),
                         ("failed", "admin", "203.0.113.5", "password"))
        self.assertEqual(ev.ts, datetime(2026, 10, 27, 3, 14, 22))

    def test_02_parse_accepted_line(self):
        line = ("Oct 27 08:00:04 srv sshd[2]: Accepted publickey for devops "
                "from 10.0.0.25 port 5555 ssh2")
        ev = parse_line(line, YEAR)
        self.assertEqual((ev.kind, ev.user, ev.ip, ev.method),
                         ("accepted", "devops", "10.0.0.25", "publickey"))

    def test_03_iso_timestamp(self):
        line = ("2026-10-27T03:14:22 srv sshd[1]: Failed password for root "
                "from 192.168.56.10 port 22 ssh2")
        ev = parse_line(line, YEAR)
        self.assertEqual(ev.ts, datetime(2026, 10, 27, 3, 14, 22))
        self.assertEqual(ev.user, "root")

    def test_04_unrelated_line_ignored(self):
        line = "Oct 27 03:14:22 srv CRON[9]: session opened for user root"
        self.assertIsNone(parse_line(line, YEAR))


class TestDetections(unittest.TestCase):
    def test_05_brute_force_detected(self):
        events = [failed(i, "ubuntu", "1.1.1.1") for i in range(12)]
        findings, _ = analyze(events)
        self.assertEqual([f["type"] for f in findings], ["SSH brute force"])
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["mitre"], "T1110.001 Password Guessing")

    def test_06_password_spraying_detected(self):
        events = []
        for n, user in enumerate(["a", "b", "c", "d", "e", "f"]):
            events += [failed(n * 10, user, "2.2.2.2"),
                       failed(n * 10 + 1, user, "2.2.2.2")]
        findings, _ = analyze(events)
        self.assertEqual([f["type"] for f in findings], ["Password spraying"])
        self.assertEqual(findings[0]["severity"], "Medium")

    def test_07_success_after_failures_detected(self):
        events = [failed(i, "ubuntu", "3.3.3.3") for i in range(6)]
        events.append(accepted(100, "ubuntu", "3.3.3.3"))
        findings, _ = analyze(events)
        types = [f["type"] for f in findings]
        self.assertIn("Success after failures", types)
        saf = [f for f in findings if f["type"] == "Success after failures"][0]
        self.assertEqual(saf["severity"], "High")

    def test_08_mistype_then_login_not_flagged(self):
        events = [failed(0, "devops", "10.0.0.25"),
                  failed(10, "devops", "10.0.0.25"),
                  accepted(20, "devops", "10.0.0.25")]
        findings, _ = analyze(events)
        self.assertEqual(findings, [])

    def test_09_failures_after_success_not_compromise(self):
        events = [accepted(0, "ubuntu", "4.4.4.4")]
        events += [failed(10 + i, "ubuntu", "4.4.4.4") for i in range(6)]
        findings, _ = analyze(events)
        self.assertNotIn("Success after failures",
                         [f["type"] for f in findings])

    def test_10_sliding_window_max(self):
        ts = [BASE + timedelta(seconds=s) for s in (0, 1, 2, 3, 100, 101)]
        self.assertEqual(max_in_window(ts, 60), 4)
        self.assertEqual(max_in_window(ts, 1000), 6)

    def test_11_same_timestamp_order_is_deterministic(self):
        # A success before same-second failures must not count those later events.
        events = [accepted(0, "ubuntu", "5.5.5.5")] + [
            failed(0, "ubuntu", "5.5.5.5") for _ in range(6)
        ]
        findings, _ = analyze(events)
        self.assertNotIn("Success after failures", [f["type"] for f in findings])

    def test_12_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            analyze([], {"bf_threshold": 0})

    def test_13_three_users_many_failures_flagged(self):
        # 60 failures over 3 users: neither "brute force" (<=2 users) nor spraying.
        events = [failed(i, "u%d" % (i % 3), "9.9.9.9") for i in range(60)]
        findings, _ = analyze(events)
        self.assertEqual([f["type"] for f in findings], ["Multi-user brute force"])
        self.assertEqual(findings[0]["severity"], "Medium")

    def test_14_many_users_high_average_flagged(self):
        # 120 failures over 6 users (avg 20): too many tries to be "spraying".
        events = [failed(i, "u%d" % (i % 6), "9.9.9.9") for i in range(120)]
        findings, _ = analyze(events)
        self.assertEqual([f["type"] for f in findings], ["Multi-user brute force"])

    def test_15_few_failures_across_users_not_flagged(self):
        # 4 users x 2 failures = 8, below the 10-failure threshold.
        events = [failed(i, "u%d" % (i % 4), "9.9.9.9") for i in range(8)]
        findings, _ = analyze(events)
        self.assertEqual(findings, [])

    def test_16_spraying_still_classified_as_spraying(self):
        events = []
        for n in range(8):
            events += [failed(n * 10, "u%d" % n, "2.2.2.2"),
                       failed(n * 10 + 1, "u%d" % n, "2.2.2.2")]
        findings, _ = analyze(events)
        self.assertEqual([f["type"] for f in findings], ["Password spraying"])

    def test_17_year_rollover_dec_to_jan(self):
        lines = ["Dec 31 23:59:%02d h sshd[1]: Failed password for ubuntu "
                 "from 8.8.8.8 port 22 ssh2" % (50 + i) for i in range(6)]
        lines.append("Jan  1 00:00:05 h sshd[1]: Accepted password for ubuntu "
                     "from 8.8.8.8 port 22 ssh2")
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write("\n".join(lines) + "\n")
            path = fh.name
        try:
            events = parse_file(path, 2026)
        finally:
            os.unlink(path)
        self.assertEqual(events[-1].ts, datetime(2027, 1, 1, 0, 0, 5))
        findings, _ = analyze(events)
        self.assertIn("Success after failures", [f["type"] for f in findings])


if __name__ == "__main__":
    unittest.main()
