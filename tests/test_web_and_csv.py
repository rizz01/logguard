import unittest
from datetime import datetime, timedelta

from logguard.detector import analyze
from logguard.parser import Event, parse_web_line
from logguard.report import to_csv

LINE = '203.0.113.60 - - [12/Aug/2026:10:03:00 +0000] "POST /login?next=/home HTTP/1.1" 401 512 "-" "Mozilla/5.0"'


class WebTests(unittest.TestCase):
    def test_parse_bad_status(self):
        e = parse_web_line(LINE)
        self.assertEqual((e.ip, e.user, e.timestamp.minute), ("203.0.113.60", "/login", 3))

    def test_ignores_ok_status(self):
        self.assertIsNone(parse_web_line(LINE.replace(" 401 ", " 200 ")))
        self.assertIsNone(parse_web_line("garbage"))

    def test_scanner_detected_in_web_mode(self):
        t0 = datetime(2026, 8, 12, 10, 0, 0)
        ev = [Event(t0 + timedelta(minutes=i), "198.51.100.33", f"/p{i}", False) for i in range(6)]
        a = analyze(ev, threshold=5, window_seconds=60, mode="web")[0]
        self.assertIn("scanning", " ".join(a.reasons))

    def test_unknown_mode(self):
        with self.assertRaises(ValueError):
            analyze([], mode="ftp")

    def test_csv_header_and_row(self):
        t0 = datetime(2026, 8, 12, 10, 0, 0)
        ev = [Event(t0 + timedelta(seconds=i), "203.0.113.1", "root", False) for i in range(6)]
        out = to_csv(analyze(ev)).splitlines()
        self.assertTrue(out[0].startswith("severity,ip"))
        self.assertIn("203.0.113.1", out[1])


if __name__ == "__main__":
    unittest.main()
