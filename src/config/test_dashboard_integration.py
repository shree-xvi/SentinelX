"""
Integration tests for SentinelX dashboard configuration.
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from config.config_loader import DEFAULT_CONFIG
from dashboard.app import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
    get_dashboard_settings,
    get_monitor_status,
)


class TestDashboardConfigIntegration(unittest.TestCase):
    """Test dashboard configuration and heartbeat integration."""

    @patch("dashboard.app.get_dashboard_config")
    def test_custom_dashboard_settings_are_loaded(self, mock_config):
        mock_config.return_value = {
            "host": "0.0.0.0",
            "port": 9090,
            "heartbeat_timeout_seconds": 30,
        }

        settings = get_dashboard_settings()

        self.assertEqual(settings["host"], "0.0.0.0")
        self.assertEqual(settings["port"], 9090)
        self.assertEqual(settings["heartbeat_timeout_seconds"], 30.0)

    @patch("dashboard.app.get_dashboard_config")
    def test_missing_settings_use_defaults(self, mock_config):
        mock_config.return_value = {}

        settings = get_dashboard_settings()

        self.assertEqual(settings["host"], DEFAULT_HOST)
        self.assertEqual(settings["port"], DEFAULT_PORT)
        self.assertEqual(
            settings["heartbeat_timeout_seconds"],
            DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        )

    @patch("dashboard.app.get_dashboard_config")
    def test_invalid_host_uses_default(self, mock_config):
        mock_config.return_value = {
            "host": "   ",
            "port": 9090,
            "heartbeat_timeout_seconds": 20,
        }

        settings = get_dashboard_settings()

        self.assertEqual(settings["host"], DEFAULT_HOST)

    @patch("dashboard.app.get_dashboard_config")
    def test_invalid_port_uses_default(self, mock_config):
        mock_config.return_value = {
            "host": "127.0.0.1",
            "port": "invalid",
            "heartbeat_timeout_seconds": 20,
        }

        settings = get_dashboard_settings()

        self.assertEqual(settings["port"], DEFAULT_PORT)

    @patch("dashboard.app.get_dashboard_config")
    def test_out_of_range_ports_use_default(self, mock_config):
        for invalid_port in (0, -1, 65536):
            with self.subTest(port=invalid_port):
                mock_config.return_value = {
                    "host": "127.0.0.1",
                    "port": invalid_port,
                    "heartbeat_timeout_seconds": 20,
                }

                settings = get_dashboard_settings()

                self.assertEqual(settings["port"], DEFAULT_PORT)

    @patch("dashboard.app.get_dashboard_config")
    def test_invalid_heartbeat_timeout_uses_default(self, mock_config):
        mock_config.return_value = {
            "host": "127.0.0.1",
            "port": 8080,
            "heartbeat_timeout_seconds": "invalid",
        }

        settings = get_dashboard_settings()

        self.assertEqual(
            settings["heartbeat_timeout_seconds"],
            DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        )

    @patch("dashboard.app.get_dashboard_config")
    def test_non_positive_heartbeat_timeout_uses_default(
        self, mock_config
    ):
        for invalid_timeout in (0, -1):
            with self.subTest(timeout=invalid_timeout):
                mock_config.return_value = {
                    "host": "127.0.0.1",
                    "port": 8080,
                    "heartbeat_timeout_seconds": invalid_timeout,
                }

                settings = get_dashboard_settings()

                self.assertEqual(
                    settings["heartbeat_timeout_seconds"],
                    DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
                )

    def test_default_dashboard_config_matches_constants(self):
        defaults = DEFAULT_CONFIG["dashboard"]

        self.assertEqual(defaults["host"], DEFAULT_HOST)
        self.assertEqual(defaults["port"], DEFAULT_PORT)
        self.assertEqual(
            defaults["heartbeat_timeout_seconds"],
            DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        )

    @patch("dashboard.app.get_dashboard_settings")
    @patch("dashboard.app.load_json_file")
    def test_expired_heartbeat_is_stopped(
        self, mock_load_json, mock_settings
    ):
        old_timestamp = (
            datetime.now().astimezone() - timedelta(seconds=60)
        ).isoformat(timespec="seconds")

        mock_load_json.return_value = {
            "status": "RUNNING",
            "message": "Monitoring logs",
            "updated_at": old_timestamp,
        }
        mock_settings.return_value = {
            "host": "127.0.0.1",
            "port": 8080,
            "heartbeat_timeout_seconds": 10,
        }

        result = get_monitor_status()

        self.assertEqual(result["status"], "STOPPED")
        self.assertEqual(
            result["message"], "Monitoring heartbeat expired."
        )

    @patch("dashboard.app.get_dashboard_settings")
    @patch("dashboard.app.load_json_file")
    def test_recent_heartbeat_remains_running(
        self, mock_load_json, mock_settings
    ):
        recent_timestamp = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        mock_load_json.return_value = {
            "status": "RUNNING",
            "message": "Monitoring logs",
            "updated_at": recent_timestamp,
        }
        mock_settings.return_value = {
            "host": "127.0.0.1",
            "port": 8080,
            "heartbeat_timeout_seconds": 30,
        }

        result = get_monitor_status()

        self.assertEqual(result["status"], "RUNNING")
        self.assertEqual(result["message"], "Monitoring logs")


if __name__ == "__main__":
    unittest.main()