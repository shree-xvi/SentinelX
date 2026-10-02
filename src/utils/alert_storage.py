
import json
from pathlib import Path

ALERTS_FILE = Path("Logs/alerts.json")


def save_alert(alert):
    """Save an alert only if it is not already stored."""

    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    if ALERTS_FILE.exists():
        with ALERTS_FILE.open("r", encoding="utf-8") as file:
            try:
                alerts = json.load(file)
            except json.JSONDecodeError:
                alerts = []
    else:
        alerts = []

    # Check whether this alert already exists
    for existing_alert in alerts:
        if (
            existing_alert.get("type") == alert.get("type")
            and existing_alert.get("source_ip") == alert.get("source_ip")
            and existing_alert.get("attempts") == alert.get("attempts")
            and existing_alert.get("time_window_minutes")
            == alert.get("time_window_minutes")
        ):
            print("[INFO] Duplicate alert skipped.")
            return False

    alerts.append(alert)

    with ALERTS_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    return True
