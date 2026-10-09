"""
SentinelX configuration loader.

Loads project configuration, validates settings, and falls back
to safe defaults when configuration values are missing or invalid.
"""

import json
from copy import deepcopy
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
    """Merge loaded settings into defaults without losing missing keys."""

    if not isinstance(default, dict):
        return loaded

    if not isinstance(loaded, dict):
        return deepcopy(default)

    merged = deepcopy(default)

    for key, value in loaded.items():
        if key not in merged:
            continue

        if isinstance(merged[key], dict):
            if isinstance(value, dict):
                merged[key] = _merge_config(merged[key], value)
        else:
            merged[key] = value

    return merged


def _is_integer(value):
    """Return True for integers, excluding booleans."""

    return isinstance(value, int) and not isinstance(value, bool)


def _validated_integer(config, section, key, minimum, maximum=None):
    """Validate an integer setting and restore its default if invalid."""

    value = config[section][key]
    default = DEFAULT_CONFIG[section][key]

    valid = _is_integer(value) and value >= minimum

    if maximum is not None:
        valid = valid and value <= maximum

    if not valid:
        config[section][key] = default


def _validate_config(config):
    """Validate all supported configuration settings."""

    detection = config["detection"]["brute_force"]

    for key, minimum in (
        ("threshold", 1),
        ("window_minutes", 1),
    ):
        value = detection[key]
        default = DEFAULT_CONFIG["detection"]["brute_force"][key]

        if not _is_integer(value) or value < minimum:
            detection[key] = default

    risk = config["risk"]

    risk_keys = (
        "medium_threshold",
        "high_threshold",
        "critical_threshold",
    )

    for key in risk_keys:
        value = risk[key]

        if not _is_integer(value) or not 0 <= value <= 100:
            risk[key] = DEFAULT_CONFIG["risk"][key]

    if not (
        risk["medium_threshold"]
        < risk["high_threshold"]
        < risk["critical_threshold"]
    ):
        config["risk"] = deepcopy(DEFAULT_CONFIG["risk"])

    _validated_integer(
        config, "monitor", "poll_seconds", minimum=1, maximum=60
    )
    _validated_integer(
        config, "monitor", "max_watch_events", minimum=1, maximum=100000
    )
    _validated_integer(
        config,
        "dashboard",
        "port",
        minimum=1,
        maximum=65535,
    )
    _validated_integer(
        config,
        "dashboard",
        "heartbeat_timeout_seconds",
        minimum=1,
        maximum=3600,
    )

    host = config["dashboard"]["host"]

    if not isinstance(host, str) or not host.strip():
        config["dashboard"]["host"] = DEFAULT_CONFIG["dashboard"]["host"]

    return config


def load_config():
    """
    Load and validate configuration.

    Missing files, invalid JSON, and unsupported root structures
    fall back to defaults.
    """

    if not CONFIG_FILE.exists():
        return deepcopy(DEFAULT_CONFIG)

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            loaded_config = json.load(file)
    except (OSError, json.JSONDecodeError):
        return deepcopy(DEFAULT_CONFIG)

    if not isinstance(loaded_config, dict):
        return deepcopy(DEFAULT_CONFIG)

    config = _merge_config(DEFAULT_CONFIG, loaded_config)

    return _validate_config(config)


def get_config_value(*keys):
    """Return a nested configuration value, or None if absent."""

    config = load_config()

    for key in keys:
        if not isinstance(config, dict) or key not in config:
            return None

        config = config[key]

    return config


def get_brute_force_config():
    """Return brute-force detection settings."""

    return get_config_value("detection", "brute_force")


def get_risk_config():
    """Return risk scoring settings."""

    return get_config_value("risk")


def get_monitor_config():
    """Return monitoring settings."""

    return get_config_value("monitor")


def get_dashboard_config():
    """Return dashboard settings."""

    return get_config_value("dashboard")