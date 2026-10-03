import json
import hashlib
from pathlib import Path


ALERTS_FILE = Path("Logs/alerts.json")


def get_alert_fingerprint(alert):
    """
    Create a stable fingerprint for an alert.

    Alerts with the same type, source IP, and incident details
    are treated as duplicates.
    """

    fingerprint_data = {
        "type": alert.get("type"),
        "source_ip": alert.get("source_ip"),
        "attempts": alert.get("attempts"),
        "failed_attempts": alert.get("failed_attempts"),
        "time_window_minutes": alert.get("time_window_minutes"),
    }

    fingerprint_string = json.dumps(
        fingerprint_data,
        sort_keys=True,
    )

    return hashlib.sha256(
        fingerprint_string.encode("utf-8")
    ).hexdigest()


def save_alert(alert):
    """
    Save an alert if an equivalent alert is not already stored.

    Returns True when saved and False when a duplicate is skipped.
    """

    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    if ALERTS_FILE.exists():
        try:
            with ALERTS_FILE.open("r", encoding="utf-8") as file:
                alerts = json.load(file)

            if not isinstance(alerts, list):
                print(
                    "[WARNING] Invalid alerts file format. "
                    "Starting with an empty alert list."
                )
                alerts = []

        except (json.JSONDecodeError, OSError):
            print(
                "[WARNING] Could not read alerts file. "
                "Starting with an empty alert list."
            )
            alerts = []
    else:
        alerts = []

    new_fingerprint = get_alert_fingerprint(alert)

    for existing_alert in alerts:
        if not isinstance(existing_alert, dict):
            continue

        existing_fingerprint = get_alert_fingerprint(existing_alert)

        if existing_fingerprint == new_fingerprint:
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