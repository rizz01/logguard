import unittest
from datetime import datetime, timedelta

from logguard.detector import analyze
from logguard.parser import Event

T0 = datetime(2026, 8, 12, 9, 0, 0)


def fails(ip, n, gap, user="root"):
    return [Event(T0 + timedelta(seconds=i * gap), ip, user, False) for i in range(n)]


class DetectorTests(unittest.TestCase):
    def test_burst_triggers_alert(self):
        alerts = analyze(fails("203.0.113.1", 6, 5), threshold=5, window_seconds=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "MEDIUM")

    def test_slow_failures_do_not_alert(self):
        self.assertEqual(analyze(fails("203.0.113.2", 6, 120), threshold=5, window_seconds=60), [])

    def test_huge_burst_is_high(self):
        self.assertEqual(analyze(fails("203.0.113.3", 20, 1), threshold=5)[0].severity, "HIGH")

    def test_success_after_failures_is_compromise(self):
        ev = fails("203.0.113.4", 6, 5) + [Event(T0 + timedelta(minutes=2), "203.0.113.4", "root", True)]
        a = analyze(ev, threshold=5)[0]
        self.assertTrue(a.possible_compromise)
        self.assertEqual(a.severity, "HIGH")

    def test_spraying_detected(self):
        ev = [Event(T0 + timedelta(minutes=i * 10), "198.51.100.9", f"user{i}", False) for i in range(6)]
        a = analyze(ev, threshold=5, window_seconds=60)[0]
        self.assertIn("spraying", " ".join(a.reasons))

    def test_invalid_settings(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)


if __name__ == "__main__":
    unittest.main()
