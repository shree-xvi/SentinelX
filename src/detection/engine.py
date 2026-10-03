from detection.brute_force import detect_brute_force
from detection.suspicious_login import detect_suspicious_login
from detection.multi_account import detect_multi_account_failures


def run_detection(events):
    """Run all SentinelX detection rules against authentication events."""
    alerts = []
    events_by_ip = {}

    for event in events:
        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        events_by_ip.setdefault(source_ip, []).append(event)

    for source_ip, ip_events in events_by_ip.items():
        # Rule 1: Detect brute-force attempts.
        failed_timestamps = [
            event["timestamp"]
            for event in ip_events
            if event.get("event_type") == "failure"
        ]

        brute_force_alert = detect_brute_force(failed_timestamps)

        if brute_force_alert:
            brute_force_alert["source_ip"] = source_ip
            alerts.append(brute_force_alert)

        # Rule 2: Detect failures followed by a successful login.
        suspicious_alert = detect_suspicious_login(ip_events)

        if suspicious_alert:
            suspicious_alert["source_ip"] = source_ip
            alerts.append(suspicious_alert)

    # Rule 3: Detect failed logins targeting multiple accounts.
    multi_account_alert = detect_multi_account_failures(events)

    if multi_account_alert:
        alerts.append(multi_account_alert)

    return alerts