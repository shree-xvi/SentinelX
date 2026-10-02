
from pathlib import Path
from datetime import datetime

from parsers.auth_log_parser import parse_failed_logins
from detection.brute_force import detect_brute_force
from utils.alert_storage import save_alert


LOG_FILE = Path("Logs/auth.log")


def main():
    """Run the SentinelX security detection pipeline."""

    print("=" * 40)
    print("       SENTINELX SECURITY MONITOR")
    print("=" * 40)

    try:
        failed_attempts = parse_failed_logins(LOG_FILE)
    except FileNotFoundError as error:
        print(f"[ERROR] {error}")
        return

    if not failed_attempts:
        print("\nNo failed login attempts found.")
        return

    print("\nAnalyzing failed login attempts...")

    alerts_found = 0
    new_alerts_saved = 0

    for ip, timestamps in failed_attempts.items():
        detection = detect_brute_force(timestamps)

        if detection is None:
            continue

        alerts_found += 1

        alert = {
            **detection,
            "source_ip": ip,
            "detected_at": datetime.now().isoformat(
                timespec="seconds"
            ),
        }

        saved = save_alert(alert)

        if not saved:
            continue

        new_alerts_saved += 1

        print("\n" + "-" * 30)
        print("SECURITY ALERT")
        print("-" * 30)
        print(f"Type: {alert['type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Attempts: {alert['attempts']}")
        print(
            f"Time Window: "
            f"{alert['time_window_minutes']} minutes"
        )
        print("Alert saved to Logs/alerts.json")

    if alerts_found == 0:
        print("\nNo brute-force attacks detected.")
    elif new_alerts_saved == 0:
        print("\nNo new alerts saved. Existing alerts were skipped.")
    else:
        print(f"\nNew alerts saved: {new_alerts_saved}")

    print("\nSentinelX scan completed.")


if __name__ == "__main__":
    main()
