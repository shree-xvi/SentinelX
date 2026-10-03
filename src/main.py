import argparse
from pathlib import Path
from datetime import datetime
import ipaddress

from parsers.auth_log_parser import parse_auth_logs
from detection.engine import run_detection
from utils.alert_storage import save_alert
from utils.alert_report import (
    load_alerts,
    generate_alert_summary,
    print_alert_summary,
    investigate_ip,
)


LOG_FILE = Path("Logs/auth.log")


def print_alert(alert):
    """Print the details of a newly saved security alert."""
    print("\n" + "-" * 40)
    print("SECURITY ALERT")
    print("-" * 40)
    print(f"Type: {alert['type']}")
    print(f"Severity: {alert['severity']}")
    print(f"Source IP: {alert['source_ip']}")

    if "attempts" in alert:
        print(f"Failed Attempts: {alert['attempts']}")

    if "failed_attempts" in alert:
        print(
            "Failed Attempts Before Success: "
            f"{alert['failed_attempts']}"
        )

    if "distinct_users" in alert:
        print(f"Distinct Usernames: {alert['distinct_users']}")

    if "time_window_minutes" in alert:
        print(f"Time Window: {alert['time_window_minutes']} minutes")

    print(f"Detected At: {alert['detected_at']}")
    print("Alert saved to Logs/alerts.json")


def run_scan():
    """Parse authentication logs and run all detection rules."""
    print("=" * 40)
    print("       SENTINELX SECURITY MONITOR")
    print("=" * 40)

    try:
        events = parse_auth_logs(LOG_FILE)
    except (FileNotFoundError, OSError) as error:
        print(f"\n[ERROR] Could not read authentication logs: {error}")
        return 1

    if not events:
        print("\nNo recognized authentication events found.")
        print("\nSentinelX scan completed.")
        return 0

    failed_count = sum(
        event["event_type"] == "failure" for event in events
    )
    success_count = sum(
        event["event_type"] == "success" for event in events
    )

    print(f"\nAuthentication events loaded: {len(events)}")
    print(f"Failed logins: {failed_count}")
    print(f"Successful logins: {success_count}")
    print("\nRunning detection engine...")

    detections = run_detection(events)

    new_alerts_saved = 0
    duplicates_skipped = 0
    save_errors = 0

    for detection in detections:
        alert = {
            **detection,
            "detected_at": datetime.now().isoformat(timespec="seconds"),
        }

        try:
            saved = save_alert(alert)
        except OSError as error:
            print(f"\n[ERROR] Could not save alert: {error}")
            save_errors += 1
            continue

        if not saved:
            duplicates_skipped += 1
            continue

        new_alerts_saved += 1
        print_alert(alert)

    print("\n" + "=" * 40)
    print(f"Alerts detected: {len(detections)}")
    print(f"New alerts saved: {new_alerts_saved}")
    print(f"Duplicate alerts skipped: {duplicates_skipped}")
    print(f"Alert save errors: {save_errors}")
    print("=" * 40)
    print("SentinelX scan completed.")

    return 1 if save_errors else 0


def run_report():
    """Display a summary of previously saved alerts."""
    try:
        alerts = load_alerts()
    except ValueError as error:
        print(f"\n[ERROR] {error}")
        return 1

    summary = generate_alert_summary(alerts)
    print_alert_summary(summary)
    return 0


def run_investigation(source_ip):
    """Validate an IP address and inspect its saved alerts."""
    try:
        parsed_ip = ipaddress.ip_address(source_ip)
    except ValueError:
        print(f"\n[ERROR] Invalid IP address: {source_ip}")
        return 2

    if not isinstance(parsed_ip, ipaddress.IPv4Address):
        print("\n[ERROR] SentinelX currently supports IPv4 investigation only.")
        return 2

    try:
        alerts = load_alerts()
    except ValueError as error:
        print(f"\n[ERROR] {error}")
        return 1

    investigate_ip(str(parsed_ip), alerts)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX authentication security monitor"
    )

    action_group = parser.add_mutually_exclusive_group()

    action_group.add_argument(
        "--report",
        action="store_true",
        help="Display a summary of saved security alerts",
    )

    action_group.add_argument(
        "--investigate",
        metavar="IP",
        help="Display saved alerts associated with an IPv4 address",
    )

    args = parser.parse_args()

    if args.report:
        return run_report()

    if args.investigate:
        return run_investigation(args.investigate)

    return run_scan()


if __name__ == "__main__":
    raise SystemExit(main())