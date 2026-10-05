"""
SentinelX configuration loader.

Loads configuration from the project-level config/sentinelx.json file
and provides safe access to configuration values.
"""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_ROOT / "config" / "sentinelx.json"


DEFAULT_CONFIG = {
    "detection": {
        "brute_force": {
            "threshold": 5,
            "window_minutes": 5,
        }
    },
    "risk": {
        "medium_threshold": 30,
        "high_threshold": 60,
        "critical_threshold": 80,
    },
    "monitor": {
        "poll_seconds": 1,
        "max_watch_events": 1000,
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8080,
        "heartbeat_timeout_seconds": 10,
    },
}


def _merge_config(default, loaded):
    """
    Recursively merge loaded configuration into the defaults.

    Missing configuration values automatically fall back to defaults.
    """

    if not isinstance(default, dict):
        return loaded

    if not isinstance(loaded, dict):
        return default.copy()

    merged = default.copy()

    for key, value in loaded.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _merge_config(merged[key], value)
        else:
            merged[key] = value

    return merged


def load_config():
    """
    Load SentinelX configuration.

    If the configuration file does not exist or contains invalid JSON,
    the default configuration is returned.
    """

    if not CONFIG_FILE.exists():
        return DEFAULT_CONFIG.copy()

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            loaded_config = json.load(file)
    except (OSError, json.JSONDecodeError):
        return DEFAULT_CONFIG.copy()

    if not isinstance(loaded_config, dict):
        return DEFAULT_CONFIG.copy()

    return _merge_config(DEFAULT_CONFIG, loaded_config)


def get_config_value(*keys):
    """
    Retrieve a nested configuration value.

    Example:

        get_config_value("detection", "brute_force", "threshold")
    """

    config = load_config()

    for key in keys:
        if not isinstance(config, dict) or key not in config:
            return None

        config = config[key]

    return config


def get_brute_force_config():
    """
    Return brute-force detection configuration.
    """

    return get_config_value("detection", "brute_force")


def get_risk_config():
    """
    Return risk scoring configuration.
    """

    return get_config_value("risk")


def get_monitor_config():
    """
    Return monitor configuration.
    """

    return get_config_value("monitor")


def get_dashboard_config():
    """
    Return dashboard configuration.
    """

    return get_config_value("dashboard")