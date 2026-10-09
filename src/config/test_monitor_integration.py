"""
Integration tests for SentinelX monitoring configuration.
"""

import unittest
from unittest.mock import patch

from config.config_loader import DEFAULT_CONFIG
from main import get_monitor_settings


class TestMonitorConfigIntegration(unittest.TestCase):
    """Verify monitor settings are read and validated correctly."""

    @patch("main.get_monitor_config")
    def test_custom_monitor_settings_are_loaded(self, mock_config):
        mock_config.return_value = {
            "poll_seconds": 3,
            "max_watch_events": 250,
        }

        settings = get_monitor_settings()

        self.assertEqual(settings["poll_seconds"], 3.0)
        self.assertEqual(settings["max_watch_events"], 250)

    @patch("main.get_monitor_config")
    def test_default_settings_when_values_are_missing(self, mock_config):
        mock_config.return_value = {}

        settings = get_monitor_settings()

        self.assertEqual(settings["poll_seconds"], 1)
        self.assertEqual(settings["max_watch_events"], 1000)

    @patch("main.get_monitor_config")
    def test_invalid_poll_interval_uses_default(self, mock_config):
        mock_config.return_value = {
            "poll_seconds": "invalid",
            "max_watch_events": 100,
        }

        settings = get_monitor_settings()

        self.assertEqual(settings["poll_seconds"], 1)

    @patch("main.get_monitor_config")
    def test_non_positive_poll_interval_uses_default(self, mock_config):
        mock_config.return_value = {
            "poll_seconds": 0,
            "max_watch_events": 100,
        }

        settings = get_monitor_settings()

        self.assertEqual(settings["poll_seconds"], 1)

    @patch("main.get_monitor_config")
    def test_invalid_event_limit_uses_default(self, mock_config):
        mock_config.return_value = {
            "poll_seconds": 2,
            "max_watch_events": "invalid",
        }

        settings = get_monitor_settings()

        self.assertEqual(settings["max_watch_events"], 1000)

    @patch("main.get_monitor_config")
    def test_non_positive_event_limit_uses_default(self, mock_config):
        mock_config.return_value = {
            "poll_seconds": 2,
            "max_watch_events": 0,
        }

        settings = get_monitor_settings()

        self.assertEqual(settings["max_watch_events"], 1000)

    @patch("main.get_monitor_config")
    def test_numeric_strings_are_supported(self, mock_config):
        mock_config.return_value = {
            "poll_seconds": "2.5",
            "max_watch_events": "400",
        }

        settings = get_monitor_settings()

        self.assertEqual(settings["poll_seconds"], 2.5)
        self.assertEqual(settings["max_watch_events"], 400)

    def test_default_constants_match_configuration_defaults(self):
        self.assertEqual(
            DEFAULT_CONFIG["monitor"]["poll_seconds"], 1
        )
        self.assertEqual(
            DEFAULT_CONFIG["monitor"]["max_watch_events"], 1000
        )


if __name__ == "__main__":
    unittest.main()