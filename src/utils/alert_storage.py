
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path


ALERTS_FILE = Path("Logs/alerts.json")

# Identical alerts are considered duplicates for this duration.
DEDUPLICATION_WINDOW_MINUTES = 30


def get_alert_fingerprint(alert):
    """
    Create a stable fingerprint from an alert's type, source IP,
    and detection details. The timestamp is deliberately excluded.
    """
    fingerprint_data = {
        "type": alert.get("type"),
        "source_ip": alert.get("source_ip"),
        "attempts": alert.get("attempts"),
        "failed_attempts": alert.get("failed_attempts"),
        "distinct_users": alert.get("distinct_users"),
        "time_window_minutes": alert.get("time_window_minutes"),
    }

    fingerprint_string = json.dumps(
        fingerprint_data,
        sort_keys=True,
    )

    return hashlib.sha256(
        fingerprint_string.encode("utf-8")
    ).hexdigest()


def parse_detected_at(alert):
    """Parse an alert timestamp, returning None when unavailable or invalid."""
    detected_at = alert.get("detected_at")

    if not isinstance(detected_at, str):
        return None

    try:
        return datetime.fromisoformat(detected_at)
    except ValueError:
        return None


def is_recent_duplicate(new_alert, existing_alert, now=None):
    """
    Return True if an equivalent alert was detected within the
    deduplication window.

    Older records without valid timestamps retain the previous
    behavior and are treated as duplicates for compatibility.
    """
    if get_alert_fingerprint(new_alert) != get_alert_fingerprint(
        existing_alert
    ):
        return False

    new_time = parse_detected_at(new_alert)
    existing_time = parse_detected_at(existing_alert)

    if new_time is None or existing_time is None:
        return True

    if now is None:
        now = new_time

    # Avoid comparing timezone-aware timestamps with naive timestamps.
    if (new_time.tzinfo is None) != (existing_time.tzinfo is None):
        return True

    age = new_time - existing_time

    if age < timedelta(0):
        return True

    return age <= timedelta(minutes=DEDUPLICATION_WINDOW_MINUTES)


def load_existing_alerts():
    """Load saved alerts, recovering safely from malformed JSON."""
    if not ALERTS_FILE.exists():
        return []

    try:
        with ALERTS_FILE.open("r", encoding="utf-8") as file:
            alerts = json.load(file)

        if isinstance(alerts, list):
            return alerts

        print(
            "[WARNING] Invalid alerts file format. "
            "Starting with an empty alert list."
        )
    except (json.JSONDecodeError, OSError):
        print(
            "[WARNING] Could not read alerts file. "
            "Starting with an empty alert list."
        )

    return []


def save_alert(alert):
    """
    Save an alert unless an equivalent alert was saved within
    the deduplication window.

    Returns True when saved and False when treated as a duplicate.
    """
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    alerts = load_existing_alerts()

    for existing_alert in alerts:
        if not isinstance(existing_alert, dict):
            continue

        if is_recent_duplicate(alert, existing_alert):
            print(
                f"[INFO] Duplicate alert skipped: "
                f"{alert.get('type')} from "
                f"{alert.get('source_ip')}"
            )
            return False

    alerts.append(alert)

    with ALERTS_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    return True
