import unittest
from unittest.mock import patch
from io import StringIO

from utils.alert_report import investigate_ip


class TestAlertInvestigation(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": "192.168.1.20",
                "attempts": 5,
                "time_window_minutes": 5,
                "detected_at": "2026-09-30T18:10:00",
            },
            {
                "type": "MULTI_ACCOUNT_FAILURES",
                "severity": "HIGH",
                "source_ip": "192.168.1.20",
                "distinct_users": 3,
                "time_window_minutes": 5,
                "detected_at": "2026-09-30T18:11:00",
            },
            {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": "192.168.1.50",
                "attempts": 5,
                "time_window_minutes": 5,
                "detected_at": "2026-09-30T18:12:00",
            },
        ]

    def test_displays_alerts_for_requested_ip(self):
        with patch("sys.stdout", new_callable=StringIO) as output:
            investigate_ip("192.168.1.20", self.alerts)

        report = output.getvalue()

        self.assertIn("Matching alerts: 2", report)
        self.assertIn("BRUTE_FORCE", report)
        self.assertIn("MULTI_ACCOUNT_FAILURES", report)
        self.assertNotIn("192.168.1.50", report)

    def test_unknown_ip_displays_no_alerts(self):
        with patch("sys.stdout", new_callable=StringIO) as output:
            investigate_ip("192.168.1.99", self.alerts)

        self.assertIn(
            "No saved alerts found for this IP address.",
            output.getvalue(),
        )

    def test_empty_alert_list(self):
        with patch("sys.stdout", new_callable=StringIO) as output:
            investigate_ip("192.168.1.20", [])

        self.assertIn(
            "No saved alerts found for this IP address.",
            output.getvalue(),
        )

    def test_displays_alert_details(self):
        with patch("sys.stdout", new_callable=StringIO) as output:
            investigate_ip("192.168.1.20", self.alerts)

        report = output.getvalue()

        self.assertIn("Failed Attempts: 5", report)
        self.assertIn("Distinct Usernames: 3", report)
        self.assertIn("2026-09-30T18:10:00", report)


if __name__ == "__main__":
    unittest.main()