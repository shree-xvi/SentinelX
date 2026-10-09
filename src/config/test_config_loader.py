"""
Tests for the SentinelX configuration loader.
"""

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from config import config_loader


class TestConfigLoader(unittest.TestCase):

    def load_from_temporary_config(self, config_data):
        """Write temporary JSON and load it through the real loader."""

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "sentinelx.json"
            config_path.write_text(
                json.dumps(config_data), encoding="utf-8"
            )

            with patch.object(config_loader, "CONFIG_FILE", config_path):
                return config_loader.load_config()

    def test_load_config_returns_expected_defaults(self):
        config = config_loader.DEFAULT_CONFIG

        self.assertEqual(
            config["detection"]["brute_force"]["threshold"], 5
        )
        self.assertEqual(config["risk"]["critical_threshold"], 80)
        self.assertEqual(config["monitor"]["poll_seconds"], 1)
        self.assertEqual(config["dashboard"]["port"], 8080)

    def test_load_config_reads_json_file(self):
        config_data = {
            "detection": {
                "brute_force": {
                    "threshold": 8,
                    "window_minutes": 3,
                }
            }
        }

        loaded = self.load_from_temporary_config(config_data)

        self.assertEqual(
            loaded["detection"]["brute_force"]["threshold"], 8
        )
        self.assertEqual(
            loaded["detection"]["brute_force"]["window_minutes"], 3
        )
        self.assertEqual(loaded["risk"]["critical_threshold"], 80)

    def test_missing_config_file_uses_defaults(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "missing.json"

            with patch.object(config_loader, "CONFIG_FILE", config_path):
                loaded = config_loader.load_config()

        self.assertEqual(loaded["monitor"]["poll_seconds"], 1)
        self.assertEqual(loaded["dashboard"]["port"], 8080)

    def test_invalid_json_uses_defaults(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "sentinelx.json"
            config_path.write_text("{invalid json", encoding="utf-8")

            with patch.object(config_loader, "CONFIG_FILE", config_path):
                loaded = config_loader.load_config()

        self.assertEqual(loaded["dashboard"]["port"], 8080)

    def test_non_dictionary_json_uses_defaults(self):
        loaded = self.load_from_temporary_config([])

        self.assertEqual(
            loaded["detection"]["brute_force"]["threshold"], 5
        )

    def test_negative_brute_force_threshold_uses_default(self):
        loaded = self.load_from_temporary_config({
            "detection": {
                "brute_force": {"threshold": -1}
            }
        })

        self.assertEqual(
            loaded["detection"]["brute_force"]["threshold"], 5
        )

    def test_string_brute_force_threshold_uses_default(self):
        loaded = self.load_from_temporary_config({
            "detection": {
                "brute_force": {"threshold": "five"}
            }
        })

        self.assertEqual(
            loaded["detection"]["brute_force"]["threshold"], 5
        )

    def test_zero_window_minutes_uses_default(self):
        loaded = self.load_from_temporary_config({
            "detection": {
                "brute_force": {"window_minutes": 0}
            }
        })

        self.assertEqual(
            loaded["detection"]["brute_force"]["window_minutes"], 5
        )

    def test_invalid_risk_threshold_uses_default(self):
        loaded = self.load_from_temporary_config({
            "risk": {"critical_threshold": 101}
        })

        self.assertEqual(loaded["risk"]["critical_threshold"], 80)

    def test_unordered_risk_thresholds_use_defaults(self):
        loaded = self.load_from_temporary_config({
            "risk": {
                "medium_threshold": 80,
                "high_threshold": 60,
                "critical_threshold": 90,
            }
        })

        self.assertEqual(loaded["risk"], config_loader.DEFAULT_CONFIG["risk"])

    def test_invalid_dashboard_port_uses_default(self):
        loaded = self.load_from_temporary_config({
            "dashboard": {"port": 70000}
        })

        self.assertEqual(loaded["dashboard"]["port"], 8080)

    def test_zero_dashboard_port_uses_default(self):
        loaded = self.load_from_temporary_config({
            "dashboard": {"port": 0}
        })

        self.assertEqual(loaded["dashboard"]["port"], 8080)

    def test_invalid_poll_interval_uses_default(self):
        loaded = self.load_from_temporary_config({
            "monitor": {"poll_seconds": -2}
        })

        self.assertEqual(loaded["monitor"]["poll_seconds"], 1)

    def test_invalid_event_limit_uses_default(self):
        loaded = self.load_from_temporary_config({
            "monitor": {"max_watch_events": 0}
        })

        self.assertEqual(loaded["monitor"]["max_watch_events"], 1000)

    def test_invalid_heartbeat_timeout_uses_default(self):
        loaded = self.load_from_temporary_config({
            "dashboard": {"heartbeat_timeout_seconds": -1}
        })

        self.assertEqual(
            loaded["dashboard"]["heartbeat_timeout_seconds"], 10
        )

    def test_empty_dashboard_host_uses_default(self):
        loaded = self.load_from_temporary_config({
            "dashboard": {"host": "   "}
        })

        self.assertEqual(loaded["dashboard"]["host"], "127.0.0.1")

    def test_boolean_threshold_uses_default(self):
        loaded = self.load_from_temporary_config({
            "detection": {
                "brute_force": {"threshold": True}
            }
        })

        self.assertEqual(
            loaded["detection"]["brute_force"]["threshold"], 5
        )

    def test_get_config_value_returns_nested_value(self):
        with patch.object(
            config_loader,
            "load_config",
            return_value=deepcopy(config_loader.DEFAULT_CONFIG),
        ):
            value = config_loader.get_config_value(
                "detection", "brute_force", "threshold"
            )

        self.assertEqual(value, 5)

    def test_get_config_value_returns_none_for_unknown_key(self):
        with patch.object(
            config_loader,
            "load_config",
            return_value=deepcopy(config_loader.DEFAULT_CONFIG),
        ):
            value = config_loader.get_config_value("unknown", "setting")

        self.assertIsNone(value)

    def test_get_brute_force_config(self):
        with patch.object(
            config_loader,
            "load_config",
            return_value=deepcopy(config_loader.DEFAULT_CONFIG),
        ):
            config = config_loader.get_brute_force_config()

        self.assertEqual(config["threshold"], 5)
        self.assertEqual(config["window_minutes"], 5)

    def test_get_risk_config(self):
        with patch.object(
            config_loader,
            "load_config",
            return_value=deepcopy(config_loader.DEFAULT_CONFIG),
        ):
            config = config_loader.get_risk_config()

        self.assertEqual(config["critical_threshold"], 80)

    def test_get_monitor_config(self):
        with patch.object(
            config_loader,
            "load_config",
            return_value=deepcopy(config_loader.DEFAULT_CONFIG),
        ):
            config = config_loader.get_monitor_config()

        self.assertEqual(config["max_watch_events"], 1000)

    def test_get_dashboard_config(self):
        with patch.object(
            config_loader,
            "load_config",
            return_value=deepcopy(config_loader.DEFAULT_CONFIG),
        ):
            config = config_loader.get_dashboard_config()

        self.assertEqual(config["host"], "127.0.0.1")
        self.assertEqual(config["port"], 8080)


if __name__ == "__main__":
    unittest.main()