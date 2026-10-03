import tempfile
import unittest
from pathlib import Path
from datetime import datetime

from parsers.auth_log_parser import (
    parse_auth_logs,
    parse_failed_logins,
    is_valid_ipv4,
)


class TestAuthLogParser(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "auth.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_log(self, content):
        self.log_file.write_text(content, encoding="utf-8")

    def test_valid_failed_login(self):
        self.write_log(
            "2026-09-30 18:03:15 WARN "
            "Login failed user=admin ip=192.168.1.10\n"
        )

        result = parse_failed_logins(self.log_file)

        self.assertIn("192.168.1.10", result)
        self.assertEqual(len(result["192.168.1.10"]), 1)

    def test_parse_successful_login(self):
        self.write_log(
            "2026-09-30 18:01:22 INFO "
            "Login successful user=admin ip=192.168.1.10\n"
        )

        events = parse_auth_logs(self.log_file)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "success")
        self.assertEqual(events[0]["username"], "admin")
        self.assertEqual(events[0]["source_ip"], "192.168.1.10")
        self.assertEqual(
            events[0]["timestamp"],
            datetime(2026, 9, 30, 18, 1, 22),
        )

    def test_parse_failed_login_as_event(self):
        self.write_log(
            "2026-09-30 18:03:15 WARN "
            "Login failed user=admin ip=192.168.1.20\n"
        )

        events = parse_auth_logs(self.log_file)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "failure")
        self.assertEqual(events[0]["username"], "admin")
        self.assertEqual(events[0]["source_ip"], "192.168.1.20")

    def test_missing_log_file(self):
        missing_file = Path(self.temp_dir.name) / "missing.log"

        with self.assertRaises(FileNotFoundError):
            parse_auth_logs(missing_file)

    def test_malformed_failed_login_is_skipped(self):
        self.write_log(
            "2026-09-30 18:03:15 WARN Login failed user=admin\n"
        )

        events = parse_auth_logs(self.log_file)

        self.assertEqual(events, [])

    def test_invalid_ipv4_address_is_skipped(self):
        self.write_log(
            "2026-09-30 18:03:15 WARN "
            "Login failed user=admin ip=999.999.999.999\n"
        )

        events = parse_auth_logs(self.log_file)

        self.assertEqual(events, [])

    def test_valid_ipv4_address_is_accepted(self):
        self.assertTrue(is_valid_ipv4("192.168.1.10"))
        self.assertTrue(is_valid_ipv4("8.8.8.8"))

    def test_invalid_ipv4_address_is_rejected(self):
        self.assertFalse(is_valid_ipv4("999.999.999.999"))
        self.assertFalse(is_valid_ipv4("192.168.1"))
        self.assertFalse(is_valid_ipv4("not-an-ip"))

    def test_username_with_special_characters(self):
        self.write_log(
            "2026-09-30 18:03:15 WARN "
            "Login failed user=service.account-1 "
            "ip=192.168.1.20\n"
        )

        events = parse_auth_logs(self.log_file)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "service.account-1")


if __name__ == "__main__":
    unittest.main()