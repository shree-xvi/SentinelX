"""
Integration tests for SentinelX configuration and brute-force detection.
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from detection.brute_force import detect_brute_force


class TestBruteForceConfigIntegration(unittest.TestCase):
    """Test configured brute-force thresholds against real detection logic."""

    def setUp(self):
        self.start_time = datetime(2026, 1, 1, 12, 0, 0)

        self.timestamps = [
            self.start_time + timedelta(seconds=30 * i)
            for i in range(5)
        ]

    @patch("detection.brute_force.get_brute_force_config")
    def test_custom_threshold_changes_brute_force_detection(
        self, mock_get_config
    ):
        """A threshold of four should alert after four attempts."""
        mock_get_config.return_value = {
            "threshold": 4,
            "window_minutes": 5,
        }

        result = detect_brute_force(self.timestamps[:4])

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "BRUTE_FORCE")
        self.assertEqual(result["attempts"], 4)
        self.assertEqual(result["time_window_minutes"], 5)

    @patch("detection.brute_force.get_brute_force_config")
    def test_custom_threshold_does_not_alert_below_threshold(
        self, mock_get_config
    ):
        """Four attempts should not alert when the threshold is five."""
        mock_get_config.return_value = {
            "threshold": 5,
            "window_minutes": 5,
        }

        result = detect_brute_force(self.timestamps[:4])

        self.assertIsNone(result)

    @patch("detection.brute_force.get_brute_force_config")
    def test_custom_time_window_is_used(
        self, mock_get_config
    ):
        """The configured time window should be reflected in the alert."""
        mock_get_config.return_value = {
            "threshold": 3,
            "window_minutes": 2,
        }

        timestamps = [
            self.start_time,
            self.start_time + timedelta(seconds=30),
            self.start_time + timedelta(minutes=1),
        ]

        result = detect_brute_force(timestamps)

        self.assertIsNotNone(result)
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["time_window_minutes"], 2)


if __name__ == "__main__":
    unittest.main()