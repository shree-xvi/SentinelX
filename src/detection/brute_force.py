"""
SentinelX brute-force detection rule.

Detects repeated failed login attempts within a configurable
time window.
"""

from datetime import timedelta

from config.config_loader import get_brute_force_config


# Default values kept for backward compatibility.
MAX_ATTEMPTS = 5
TIME_WINDOW_MINUTES = 5


def detect_brute_force(failed_timestamps):
    """
    Detect brute-force activity from failed login timestamps.

    Detection thresholds are loaded from config/sentinelx.json.
    """

    config = get_brute_force_config()

    threshold = config.get("threshold", MAX_ATTEMPTS)
    window_minutes = config.get(
        "window_minutes",
        TIME_WINDOW_MINUTES,
    )

    try:
        threshold = int(threshold)
    except (TypeError, ValueError):
        threshold = MAX_ATTEMPTS

    try:
        window_minutes = int(window_minutes)
    except (TypeError, ValueError):
        window_minutes = TIME_WINDOW_MINUTES

    failed_timestamps.sort()

    time_window = timedelta(minutes=window_minutes)

    for i in range(len(failed_timestamps)):
        window_start = failed_timestamps[i]

        attempts_in_window = 0

        for timestamp in failed_timestamps[i:]:
            if timestamp - window_start <= time_window:
                attempts_in_window += 1
            else:
                break

        if attempts_in_window >= threshold:
            return {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "attempts": attempts_in_window,
                "time_window_minutes": window_minutes,
            }

    return None