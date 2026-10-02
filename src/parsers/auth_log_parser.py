
import re
import ipaddress
from pathlib import Path
from datetime import datetime
from collections import defaultdict


TIMESTAMP_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def is_valid_ipv4(address):
    """Return True only if the address is a valid IPv4 address."""
    try:
        parsed_address = ipaddress.ip_address(address)
        return isinstance(parsed_address, ipaddress.IPv4Address)
    except ValueError:
        return False


def parse_failed_logins(log_file):
    """Parse failed login events and group timestamps by valid source IP."""

    failed_attempts = defaultdict(list)
    log_file = Path(log_file)

    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    with log_file.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if "Login failed" not in line:
                continue

            timestamp_match = TIMESTAMP_PATTERN.search(line)
            ip_match = IP_PATTERN.search(line)

            if not timestamp_match or not ip_match:
                print(
                    f"[WARNING] Skipping malformed log entry "
                    f"on line {line_number}."
                )
                continue

            try:
                timestamp = datetime.strptime(
                    timestamp_match.group(1),
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError:
                print(
                    f"[WARNING] Invalid timestamp on line {line_number}."
                )
                continue

            source_ip = ip_match.group(0)

            if not is_valid_ipv4(source_ip):
                print(
                    f"[WARNING] Invalid IP address on line {line_number}."
                )
                continue

            failed_attempts[source_ip].append(timestamp)

    return dict(failed_attempts)
