
import re
import ipaddress
from pathlib import Path
from datetime import datetime


TIMESTAMP_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
)

IP_PATTERN = re.compile(
    r"\bip=((?:\d{1,3}\.){3}\d{1,3})\b"
)

USERNAME_PATTERN = re.compile(
    r"\buser=([A-Za-z0-9_.@-]+)\b"
)


def is_valid_ipv4(address):
    """Return True only if the address is a valid IPv4 address."""
    try:
        parsed_address = ipaddress.ip_address(address)
        return isinstance(parsed_address, ipaddress.IPv4Address)
    except ValueError:
        return False


def parse_auth_line(line, line_number=None):
    """
    Parse one authentication log line.

    Return an event dictionary for a valid login event, or None if the
    line is unrelated or malformed.
    """
    if "Login failed" in line:
        event_type = "failure"
    elif "Login successful" in line:
        event_type = "success"
    else:
        return None

    timestamp_match = TIMESTAMP_PATTERN.search(line)
    ip_match = IP_PATTERN.search(line)
    username_match = USERNAME_PATTERN.search(line)

    if not timestamp_match or not ip_match or not username_match:
        location = (
            f" on line {line_number}"
            if line_number is not None
            else ""
        )
        print(f"[WARNING] Skipping malformed log entry{location}.")
        return None

    try:
        timestamp = datetime.strptime(
            timestamp_match.group(1),
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        location = (
            f" on line {line_number}"
            if line_number is not None
            else ""
        )
        print(f"[WARNING] Invalid timestamp{location}.")
        return None

    source_ip = ip_match.group(1)
    username = username_match.group(1)

    if not is_valid_ipv4(source_ip):
        location = (
            f" on line {line_number}"
            if line_number is not None
            else ""
        )
        print(f"[WARNING] Invalid IP address{location}.")
        return None

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
    }


def parse_auth_logs(log_file):
    """
    Parse successful and failed login events from a log file.
    """
    log_file = Path(log_file)

    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    events = []

    with log_file.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            event = parse_auth_line(line, line_number)

            if event is not None:
                events.append(event)

    return events


def parse_failed_logins(log_file):
    """
    Compatibility function returning failed timestamps grouped by IP.
    """
    failed_attempts = {}

    for event in parse_auth_logs(log_file):
        if event["event_type"] != "failure":
            continue

        source_ip = event["source_ip"]
        failed_attempts.setdefault(source_ip, []).append(
            event["timestamp"]
        )

    return failed_attempts
