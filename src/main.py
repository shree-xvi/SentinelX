
import argparse
import ipaddress
import json
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from parsers.auth_log_parser import parse_auth_logs, parse_auth_line
from detection.engine import run_detection
from utils.alert_storage import save_alert
from utils.alert_report import (
    load_alerts,
    generate_alert_summary,
    print_alert_summary,
)


LOG_FILE = Path("Logs/auth.log")
WATCH_POLL_SECONDS = 1
MAX_WATCH_EVENTS = 1000

# The dashboard reads this file to display monitor status.
STATUS_FILE = Path(__file__).resolve().parent / "dashboard" / "status.json"


def write_monitor_status(status, message):
    """Write the current monitoring status for the dashboard."""
    data = {
        "status": status,
        "message": message,
        "updated_at": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
    }

    try:
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary_file = STATUS_FILE.with_suffix(".tmp")

        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        temporary_file.replace(STATUS_FILE)
    except OSError as error:
        print(f"[WARNING] Could not update dashboard status: {error}")


def get_file_identity(log_file):
    """Return file identity for detecting replacement or rotation."""
    stat_result = Path(log_file).stat()
    return stat_result.st_dev, stat_result.st_ino


def should_reset_log(new_size, old_size, new_identity, old_identity):
    """Return True when a log appears truncated or replaced."""
    return new_size < old_size or new_identity != old_identity


def print_alert(alert):
    """Print details of a newly saved security alert."""
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


def process_detections(events):
    """Detect, save, and display alerts for a collection of events."""
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
        except (OSError, ValueError) as error:
            print(f"\n[ERROR] Could not save alert: {error}")
            save_errors += 1
            continue

        if not saved:
            duplicates_skipped += 1
            print(
                "[INFO] Duplicate alert skipped: "
                f"{alert.get('type', 'UNKNOWN')} from "
                f"{alert.get('source_ip', 'UNKNOWN')}"
            )
            continue

        new_alerts_saved += 1
        print_alert(alert)

    return {
        "detected": len(detections),
        "saved": new_alerts_saved,
        "duplicates": duplicates_skipped,
        "errors": save_errors,
    }


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

    results = process_detections(events)

    print("\n" + "=" * 40)
    print(f"Alerts detected: {results['detected']}")
    print(f"New alerts saved: {results['saved']}")
    print(f"Duplicate alerts skipped: {results['duplicates']}")
    print(f"Alert save errors: {results['errors']}")
    print("=" * 40)
    print("SentinelX scan completed.")

    return 1 if results["errors"] else 0


def read_new_events(log_file, offset, pending_bytes=b""):
    """Read complete appended lines and retain any partial final line."""
    log_file = Path(log_file)

    with log_file.open("rb") as file:
        file.seek(offset)
        new_bytes = file.read()
        new_offset = file.tell()

    combined = pending_bytes + new_bytes
    last_newline = combined.rfind(b"\n")

    if last_newline == -1:
        return [], offset, combined

    complete_bytes = combined[:last_newline + 1]
    remaining_bytes = combined[last_newline + 1:]
    text = complete_bytes.decode("utf-8", errors="replace")

    events = []

    for line in text.splitlines():
        event = parse_auth_line(line)
        if event is not None:
            events.append(event)

    return events, new_offset, remaining_bytes


def run_watch(log_file=LOG_FILE, poll_seconds=WATCH_POLL_SECONDS):
    """Watch authentication logs and publish the monitor's status."""
    log_file = Path(log_file)

    if poll_seconds <= 0:
        print("\n[ERROR] Poll interval must be greater than zero.")
        return 2

    if not log_file.exists():
        print(f"\n[ERROR] Log file not found: {log_file}")
        return 1

    try:
        initial_events = parse_auth_logs(log_file)
        offset = log_file.stat().st_size
        file_identity = get_file_identity(log_file)
    except (FileNotFoundError, OSError) as error:
        print(f"\n[ERROR] Could not read authentication logs: {error}")
        return 1

    recent_events = deque(initial_events, maxlen=MAX_WATCH_EVENTS)
    pending_bytes = b""

    print("=" * 40)
    print("       SENTINELX LIVE MONITOR")
    print("=" * 40)
    print(f"Watching: {log_file}")
    print(f"Initial events loaded: {len(initial_events)}")
    print("Waiting for new authentication events...")
    print("Press Ctrl+C to stop.\n")

    write_monitor_status(
        "RUNNING",
        f"Watching {log_file.as_posix()} for new authentication events.",
    )

    try:
        while True:
            # Refresh the heartbeat so the dashboard can detect stale status.
            write_monitor_status(
                "RUNNING",
                "Monitoring authentication logs for new events.",
            )

            if not log_file.exists():
                print(f"[WARNING] Log file not found: {log_file}")
                time.sleep(poll_seconds)
                continue

            try:
                current_size = log_file.stat().st_size
                current_identity = get_file_identity(log_file)

                if should_reset_log(
                    current_size,
                    offset,
                    current_identity,
                    file_identity,
                ):
                    if current_identity != file_identity:
                        print(
                            "[INFO] Log file replacement detected; "
                            "resetting the read position."
                        )
                    else:
                        print(
                            "[INFO] Log file was truncated; "
                            "resetting the read position."
                        )

                    offset = 0
                    pending_bytes = b""
                    recent_events.clear()
                    file_identity = current_identity

                events, new_offset, pending_bytes = read_new_events(
                    log_file,
                    offset,
                    pending_bytes,
                )
                offset = new_offset

            except FileNotFoundError:
                print(
                    "[INFO] Log file changed during reading; "
                    "will retry."
                )
                time.sleep(poll_seconds)
                continue
            except OSError as error:
                print(f"[WARNING] Could not read log file: {error}")
                time.sleep(poll_seconds)
                continue

            if events:
                for event in events:
                    recent_events.append(event)

                print(f"[INFO] Processed {len(events)} new event(s).")
                results = process_detections(list(recent_events))

                if results["errors"]:
                    print(
                        f"[WARNING] {results['errors']} alert(s) "
                        "could not be saved."
                    )

            time.sleep(poll_seconds)

    except KeyboardInterrupt:
        print("\n[INFO] Live monitoring stopped.")
        return 0
    finally:
        write_monitor_status(
            "STOPPED",
            "Live monitoring has stopped.",
        )


def run_report():
    """Display a summary of saved alerts."""
    try:
        alerts = load_alerts()
    except (ValueError, OSError) as error:
        print(f"\n[ERROR] Could not load alert report: {error}")
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
        print(
            "\n[ERROR] SentinelX currently supports "
            "IPv4 investigation only."
        )
        return 2

    try:
        alerts = load_alerts()
    except (ValueError, OSError) as error:
        print(f"\n[ERROR] Could not load alerts: {error}")
        return 1

    investigate_ip(str(parsed_ip), alerts)
    return 0


def main():
    """Parse CLI arguments and run the selected SentinelX command."""
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
    action_group.add_argument(
        "--watch",
        action="store_true",
        help="Watch the authentication log for new events",
    )

    args = parser.parse_args()

    if args.report:
        return run_report()

    if args.investigate:
        return run_investigation(args.investigate)

    if args.watch:
        return run_watch()

    return run_scan()


if __name__ == "__main__":
    raise SystemExit(main())
