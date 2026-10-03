from collections import Counter
from pathlib import Path
import json


ALERTS_FILE = Path("Logs/alerts.json")


def load_alerts(file_path=ALERTS_FILE):
    """Load saved alerts from a JSON file."""
    file_path = Path(file_path)

    if not file_path.exists():
        return []

    try:
        with file_path.open("r", encoding="utf-8") as file:
            alerts = json.load(file)
    except (json.JSONDecodeError, OSError) as error:
        raise ValueError(
            f"Could not read alerts file '{file_path}': {error}"
        ) from error

    if not isinstance(alerts, list):
        raise ValueError("Alerts file must contain a JSON list.")

    return [
        alert for alert in alerts
        if isinstance(alert, dict)
    ]


def generate_alert_summary(alerts):
    """Generate summary statistics for saved alerts."""
    severity_counts = Counter()
    type_counts = Counter()
    source_ip_counts = Counter()

    for alert in alerts:
        severity_counts[alert.get("severity", "UNKNOWN")] += 1
        type_counts[alert.get("type", "UNKNOWN")] += 1
        source_ip_counts[alert.get("source_ip", "UNKNOWN")] += 1

    return {
        "total_alerts": len(alerts),
        "by_severity": dict(severity_counts),
        "by_type": dict(type_counts),
        "by_source_ip": dict(source_ip_counts),
    }


def print_alert_summary(summary):
    """Print a readable summary of saved security alerts."""
    print("\n" + "=" * 45)
    print("          SENTINELX ALERT REPORT")
    print("=" * 45)

    print(f"Total saved alerts: {summary['total_alerts']}")

    print("\nAlerts by severity:")
    if summary["by_severity"]:
        for severity, count in sorted(summary["by_severity"].items()):
            print(f"  {severity}: {count}")
    else:
        print("  No alerts recorded.")

    print("\nAlerts by detection rule:")
    if summary["by_type"]:
        for alert_type, count in sorted(summary["by_type"].items()):
            print(f"  {alert_type}: {count}")
    else:
        print("  No alerts recorded.")

    print("\nAlerts by source IP:")
    if summary["by_source_ip"]:
        for source_ip, count in sorted(summary["by_source_ip"].items()):
            print(f"  {source_ip}: {count}")
    else:
        print("  No alerts recorded.")

    print("=" * 45)


def investigate_ip(source_ip, alerts):
    """Display saved security alerts associated with a source IP."""
    matching_alerts = [
        alert
        for alert in alerts
        if alert.get("source_ip") == source_ip
    ]

    print("\n" + "=" * 45)
    print(f"       INVESTIGATION: {source_ip}")
    print("=" * 45)

    if not matching_alerts:
        print("No saved alerts found for this IP address.")
        print("=" * 45)
        return

    print(f"Matching alerts: {len(matching_alerts)}")

    for index, alert in enumerate(matching_alerts, start=1):
        print(f"\nAlert #{index}")
        print(f"Type: {alert.get('type', 'UNKNOWN')}")
        print(f"Severity: {alert.get('severity', 'UNKNOWN')}")
        print(f"Source IP: {alert.get('source_ip', 'UNKNOWN')}")
        print(f"Detected At: {alert.get('detected_at', 'UNKNOWN')}")

        detail_fields = {
            "attempts": "Failed Attempts",
            "failed_attempts": "Failed Attempts Before Success",
            "distinct_users": "Distinct Usernames",
            "time_window_minutes": "Time Window (minutes)",
        }

        for field, label in detail_fields.items():
            if field in alert:
                print(f"{label}: {alert[field]}")

    print("\n" + "=" * 45)