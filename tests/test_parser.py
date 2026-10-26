import unittest

from logguard.parser import parse_line


class ParserTests(unittest.TestCase):
    def test_failed_password(self):
        e = parse_line("Aug 12 09:05:00 srv sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2", 2026)
        self.assertEqual((e.ip, e.user, e.success), ("203.0.113.45", "root", False))

    def test_invalid_user_and_single_digit_day(self):
        e = parse_line("Aug  2 09:05:00 srv sshd[1]: Failed password for invalid user git from 198.51.100.7 port 22 ssh2", 2026)
        self.assertEqual((e.user, e.timestamp.day), ("git", 2))

    def test_accepted(self):
        e = parse_line("Aug 12 09:00:20 srv sshd[1]: Accepted publickey for alice from 192.0.2.10 port 22 ssh2", 2026)
        self.assertTrue(e.success)

    def test_unrelated_line(self):
        self.assertIsNone(parse_line("Aug 12 09:00:05 srv CRON[1]: session opened for user root", 2026))
        self.assertIsNone(parse_line("not a log line", 2026))


if __name__ == "__main__":
    unittest.main()
