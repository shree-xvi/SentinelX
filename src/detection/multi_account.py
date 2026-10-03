from collections import defaultdict


MIN_DISTINCT_USERS = 3
TIME_WINDOW_MINUTES = 5


def detect_multi_account_failures(events):
    """
    Detect failed logins against multiple distinct usernames
    from the same IP address within a five-minute window.
    """
    failures_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type") != "failure":
            continue

        source_ip = event.get("source_ip")
        username = event.get("username")
        timestamp = event.get("timestamp")

        if not source_ip or not username or timestamp is None:
            continue

        failures_by_ip[source_ip].append({
            "timestamp": timestamp,
            "username": username,
        })

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])

        for start_index, first_failure in enumerate(failures):
            window_start = first_failure["timestamp"]
            usernames = set()

            for failure in failures[start_index:]:
                elapsed = failure["timestamp"] - window_start

                if elapsed.total_seconds() > TIME_WINDOW_MINUTES * 60:
                    break

                usernames.add(failure["username"])

                if len(usernames) >= MIN_DISTINCT_USERS:
                    return {
                        "type": "MULTI_ACCOUNT_FAILURES",
                        "severity": "HIGH",
                        "source_ip": source_ip,
                        "distinct_users": len(usernames),
                        "time_window_minutes": TIME_WINDOW_MINUTES,
                    }

    return None