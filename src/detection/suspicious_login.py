
from datetime import timedelta


MIN_FAILED_ATTEMPTS = 3
TIME_WINDOW_MINUTES = 5


def detect_suspicious_login(events):
    """
    Detect a successful login from an IP address after
    at least three failed attempts within five minutes.

    Each event should be a dictionary containing:
    - timestamp: a datetime object
    - source_ip: an IP address string
    - event_type: "failure" or "success"
    """

    events = sorted(events, key=lambda event: event["timestamp"])
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    failures_by_ip = {}

    for event in events:
        timestamp = event["timestamp"]
        source_ip = event["source_ip"]
        event_type = event["event_type"]

        if event_type == "failure":
            failures_by_ip.setdefault(source_ip, []).append(timestamp)

        elif event_type == "success":
            failures = failures_by_ip.get(source_ip, [])

            recent_failures = [
                failed_at
                for failed_at in failures
                if timedelta(0) <= timestamp - failed_at <= window
            ]

            if len(recent_failures) >= MIN_FAILED_ATTEMPTS:
                return {
                    "type": "SUSPICIOUS_LOGIN_AFTER_FAILURES",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "failed_attempts": len(recent_failures),
                    "time_window_minutes": TIME_WINDOW_MINUTES,
                }

    return None
