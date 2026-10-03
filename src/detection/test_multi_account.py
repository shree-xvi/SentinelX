import unittest
from datetime import datetime, timedelta

from detection.multi_account import detect_multi_account_failures


class TestMultiAccountDetection(unittest.TestCase):

    def setUp(self):
        self.start_time = datetime(2026, 9, 30, 18, 10, 0)

    def make_event(
        self,
        seconds,
        username,
        source_ip="192.168.1.50",
        event_type="failure",
    ):
        return {
            "timestamp": self.start_time + timedelta(seconds=seconds),
            "source_ip": source_ip,
            "username": username,
            "event_type": event_type,
        }

    def test_detects_failures_against_three_users(self):
        events = [
            self.make_event(0, "admin"),
            self.make_event(10, "shree"),
            self.make_event(20, "service"),
        ]

        alert = detect_multi_account_failures(events)

        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "MULTI_ACCOUNT_FAILURES")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["source_ip"], "192.168.1.50")
        self.assertEqual(alert["distinct_users"], 3)

    def test_repeated_failures_against_one_user_do_not_alert(self):
        events = [
            self.make_event(0, "admin"),
            self.make_event(10, "admin"),
            self.make_event(20, "admin"),
        ]

        self.assertIsNone(detect_multi_account_failures(events))

    def test_only_two_distinct_users_do_not_alert(self):
        events = [
            self.make_event(0, "admin"),
            self.make_event(10, "shree"),
            self.make_event(20, "admin"),
        ]

        self.assertIsNone(detect_multi_account_failures(events))

    def test_failures_outside_window_do_not_combine(self):
        events = [
            self.make_event(0, "admin"),
            self.make_event(301, "shree"),
            self.make_event(302, "service"),
        ]

        self.assertIsNone(detect_multi_account_failures(events))

    def test_successful_logins_do_not_count(self):
        events = [
            self.make_event(0, "admin", event_type="success"),
            self.make_event(10, "shree"),
            self.make_event(20, "service"),
        ]

        self.assertIsNone(detect_multi_account_failures(events))

    def test_different_ips_do_not_combine(self):
        events = [
            self.make_event(0, "admin", "192.168.1.50"),
            self.make_event(10, "shree", "192.168.1.51"),
            self.make_event(20, "service", "192.168.1.52"),
        ]

        self.assertIsNone(detect_multi_account_failures(events))

    def test_empty_events_do_not_alert(self):
        self.assertIsNone(detect_multi_account_failures([]))

    def test_exactly_five_minutes_is_included(self):
        events = [
            self.make_event(0, "admin"),
            self.make_event(150, "shree"),
            self.make_event(300, "service"),
        ]

        alert = detect_multi_account_failures(events)

        self.assertIsNotNone(alert)
        self.assertEqual(alert["distinct_users"], 3)


if __name__ == "__main__":
    unittest.main()