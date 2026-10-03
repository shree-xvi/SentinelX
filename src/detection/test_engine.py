import unittest
from datetime import datetime, timedelta

from detection.engine import run_detection


class TestDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.start_time = datetime(2026, 9, 30, 18, 10, 0)

    def make_event(
        self,
        seconds,
        username="admin",
        source_ip="192.168.1.50",
        event_type="failure",
    ):
        return {
            "timestamp": self.start_time + timedelta(seconds=seconds),
            "source_ip": source_ip,
            "username": username,
            "event_type": event_type,
        }

    def test_brute_force_detection(self):
        events = [
            self.make_event(0),
            self.make_event(30),
            self.make_event(60),
            self.make_event(90),
            self.make_event(120),
        ]

        alerts = run_detection(events)

        self.assertTrue(
            any(alert["type"] == "BRUTE_FORCE" for alert in alerts)
        )

    def test_suspicious_login_detection(self):
        events = [
            self.make_event(0),
            self.make_event(10),
            self.make_event(20),
            self.make_event(
                30,
                event_type="success",
            ),
        ]

        alerts = run_detection(events)

        self.assertTrue(
            any(
                alert["type"] == "SUSPICIOUS_LOGIN_AFTER_FAILURES"
                for alert in alerts
            )
        )

    def test_different_ips_do_not_trigger_suspicious_login(self):
        events = [
            self.make_event(0, source_ip="192.168.1.50"),
            self.make_event(10, source_ip="192.168.1.50"),
            self.make_event(20, source_ip="192.168.1.50"),
            self.make_event(
                30,
                source_ip="192.168.1.51",
                event_type="success",
            ),
        ]

        alerts = run_detection(events)

        self.assertFalse(
            any(
                alert["type"] == "SUSPICIOUS_LOGIN_AFTER_FAILURES"
                for alert in alerts
            )
        )

    def test_multi_account_detection(self):
        events = [
            self.make_event(0, username="admin"),
            self.make_event(10, username="shree"),
            self.make_event(20, username="service"),
        ]

        alerts = run_detection(events)

        multi_account_alerts = [
            alert
            for alert in alerts
            if alert["type"] == "MULTI_ACCOUNT_FAILURES"
        ]

        self.assertEqual(len(multi_account_alerts), 1)
        self.assertEqual(
            multi_account_alerts[0]["source_ip"],
            "192.168.1.50",
        )
        self.assertEqual(
            multi_account_alerts[0]["distinct_users"],
            3,
        )

    def test_different_ips_do_not_combine_multi_account_failures(self):
        events = [
            self.make_event(
                0, username="admin", source_ip="192.168.1.50"
            ),
            self.make_event(
                10, username="shree", source_ip="192.168.1.51"
            ),
            self.make_event(
                20, username="service", source_ip="192.168.1.52"
            ),
        ]

        alerts = run_detection(events)

        self.assertFalse(
            any(
                alert["type"] == "MULTI_ACCOUNT_FAILURES"
                for alert in alerts
            )
        )


if __name__ == "__main__":
    unittest.main()