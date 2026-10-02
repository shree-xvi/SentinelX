
import sys
import tempfile
import unittest
from pathlib import Path
from datetime import datetime


# Make the src directory available for imports
SRC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC_DIR))

from parsers.auth_log_parser import parse_failed_logins


class TestAuthLogParser(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "auth.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_failed_login(self):
        self.log_file.write_text(
            "2026-10-02 10:00:00 Login failed from 192.168.1.20\n",
            encoding="utf-8",
        )

        result = parse_failed_logins(self.log_file)

        self.assertIn("192.168.1.20", result)
        self.assertEqual(
            result["192.168.1.20"],
            [datetime(2026, 10, 2, 10, 0, 0)],
        )

    def test_malformed_failed_login_is_skipped(self):
        self.log_file.write_text(
            "Login failed from an unknown address\n",
            encoding="utf-8",
        )

        result = parse_failed_logins(self.log_file)

        self.assertEqual(result, {})

    def test_missing_log_file(self):
        missing_file = Path(self.temp_dir.name) / "missing.log"

        with self.assertRaises(FileNotFoundError):
            parse_failed_logins(missing_file)

    def test_invalid_ipv4_address_is_skipped(self):
        self.log_file.write_text(
            "2026-10-02 10:00:00 Login failed from 999.999.999.999\n",
            encoding="utf-8",
        )

        result = parse_failed_logins(self.log_file)

        self.assertEqual(result, {})

    def test_valid_ipv4_address_is_accepted(self):
        self.log_file.write_text(
            "2026-10-02 10:00:00 Login failed from 192.168.1.20\n",
            encoding="utf-8",
        )

        result = parse_failed_logins(self.log_file)

        self.assertIn("192.168.1.20", result)
        self.assertEqual(len(result["192.168.1.20"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
