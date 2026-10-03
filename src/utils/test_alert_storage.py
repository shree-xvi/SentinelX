import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from utils import alert_storage


class TestAlertStorage(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.alerts_file = Path(self.temp_dir.name) / "alerts.json"

        self.file_patcher = patch.object(
            alert_storage,
            "ALERTS_FILE",
            self.alerts_file,
        )
        self.file_patcher.start()
        self.addCleanup(self.file_patcher.stop)

        self.addCleanup(self.temp_dir.cleanup)

    def sample_alert(self):
        return {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": "192.168.1.20",
            "attempts": 5,
            "time_window_minutes": 5,
            "detected_at": "2026-10-03T10:00:00",
        }

    def test_new_alert_is_saved(self):
        alert = self.sample_alert()

        result = alert_storage.save_alert(alert)

        self.assertTrue(result)
        self.assertTrue(self.alerts_file.exists())

        with self.alerts_file.open("r", encoding="utf-8") as file:
            saved_alerts = json.load(file)

        self.assertEqual(len(saved_alerts), 1)
        self.assertEqual(saved_alerts[0]["type"], "BRUTE_FORCE")

    def test_duplicate_alert_is_not_saved_twice(self):
        alert = self.sample_alert()

        self.assertTrue(alert_storage.save_alert(alert))
        self.assertFalse(alert_storage.save_alert(alert))

        with self.alerts_file.open("r", encoding="utf-8") as file:
            saved_alerts = json.load(file)

        self.assertEqual(len(saved_alerts), 1)

    def test_different_source_ip_is_saved(self):
        first_alert = self.sample_alert()
        second_alert = self.sample_alert()
        second_alert["source_ip"] = "192.168.1.30"

        self.assertTrue(alert_storage.save_alert(first_alert))
        self.assertTrue(alert_storage.save_alert(second_alert))

        with self.alerts_file.open("r", encoding="utf-8") as file:
            saved_alerts = json.load(file)

        self.assertEqual(len(saved_alerts), 2)

    def test_different_alert_type_is_saved(self):
        first_alert = self.sample_alert()
        second_alert = self.sample_alert()
        second_alert["type"] = "SUSPICIOUS_LOGIN_AFTER_FAILURES"
        second_alert.pop("attempts")
        second_alert["failed_attempts"] = 3

        self.assertTrue(alert_storage.save_alert(first_alert))
        self.assertTrue(alert_storage.save_alert(second_alert))

        with self.alerts_file.open("r", encoding="utf-8") as file:
            saved_alerts = json.load(file)

        self.assertEqual(len(saved_alerts), 2)


if __name__ == "__main__":
    unittest.main()