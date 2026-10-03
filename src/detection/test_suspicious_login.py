
import unittest
from datetime import datetime, timedelta

from detection.suspicious_login import detect_suspicious_login


class TestSuspiciousLogin(unittest.TestCase):

    def setUp(self):
        self.start = datetime(2026, 10, 3, 10, 0, 0)

    def make_event(self, minutes, seconds, event_type, source_ip="192.168.1.20"):
        return {
            "timestamp": self.start + timedelta(
                minutes=minutes,
                seconds=seconds
            ),
            "source_ip": source_ip,
            "event_type": event_type,
        }

    def test_alert_after_three_failures_and_success(self):
        events = [
            self.make_event(0, 0, "failure"),
            self.make_event(0, 20, "failure"),
            self.make_event(1, 0, "failure"),
            self.make_event(1, 10, "success"),
        ]

        alert = detect_suspicious_login(events)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["type"],
            "SUSPICIOUS_LOGIN_AFTER_FAILURES"
        )
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["source_ip"], "192.168.1.20")
        self.assertEqual(alert["failed_attempts"], 3)

    def test_no_alert_with_only_two_failures(self):
        events = [
            self.make_event(0, 0, "failure"),
            self.make_event(0, 20, "failure"),
            self.make_event(1, 0, "success"),
        ]

        self.assertIsNone(detect_suspicious_login(events))

    def test_no_alert_when_success_is_outside_window(self):
        events = [
            self.make_event(0, 0, "failure"),
            self.make_event(0, 20, "failure"),
            self.make_event(1, 0, "failure"),
            self.make_event(6, 0, "success"),
        ]

        self.assertIsNone(detect_suspicious_login(events))

    def test_failures_from_another_ip_do_not_count(self):
        events = [
            self.make_event(0, 0, "failure", "192.168.1.10"),
            self.make_event(0, 20, "failure", "192.168.1.10"),
            self.make_event(1, 0, "failure", "192.168.1.10"),
            self.make_event(1, 10, "success", "192.168.1.20"),
        ]

        self.assertIsNone(detect_suspicious_login(events))

    def test_empty_events_do_not_trigger_alert(self):
        self.assertIsNone(detect_suspicious_login([]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
