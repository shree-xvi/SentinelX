
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from utils.alert_storage import (
    get_alert_fingerprint,
    is_recent_duplicate,
)


class TestAlertDeduplication(unittest.TestCase):
    def setUp(self):
        self.alert = {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": "192.168.1.99",
            "attempts": 5,
            "time_window_minutes": 5,
            "detected_at": "2026-10-03T12:00:00",
        }

    def test_identical_alerts_have_same_fingerprint(self):
        first = dict(self.alert)
        second = dict(self.alert)
        second["detected_at"] = "2026-10-03T12:10:00"

        self.assertEqual(
            get_alert_fingerprint(first),
            get_alert_fingerprint(second),
        )

    def test_same_incident_within_window_is_duplicate(self):
        first = dict(self.alert)
        second = dict(self.alert)
        second["detected_at"] = "2026-10-03T12:20:00"

        self.assertTrue(is_recent_duplicate(second, first))

    def test_same_incident_after_window_is_not_duplicate(self):
        first = dict(self.alert)
        second = dict(self.alert)
        second["detected_at"] = "2026-10-03T12:31:00"

        self.assertFalse(is_recent_duplicate(second, first))

    def test_different_source_ip_is_not_duplicate(self):
        first = dict(self.alert)
        second = dict(self.alert)
        second["source_ip"] = "192.168.1.100"
        second["detected_at"] = "2026-10-03T12:05:00"

        self.assertFalse(is_recent_duplicate(second, first))

    def test_legacy_alert_without_timestamp_is_duplicate(self):
        first = dict(self.alert)
        first.pop("detected_at")

        second = dict(self.alert)
        second["detected_at"] = "2026-10-03T12:05:00"

        self.assertTrue(is_recent_duplicate(second, first))


if __name__ == "__main__":
    unittest.main()
