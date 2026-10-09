import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from agent.collectors.base import BaseCollector

TIMESTAMP_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
IP_PATTERN = re.compile(r"\bip=((?:\d{1,3}\.){3}\d{1,3})\b")
USER_PATTERN = re.compile(r"\buser=([A-Za-z0-9_.@-]+)\b")


class AuthCollector(BaseCollector):
    name = "auth"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.log_path = Path(self.config.get("log_path", "Logs/auth.log"))
        self._offset = 0

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None

        event_type = None
        if "Login failed" in line:
            event_type = "auth_failure"
        elif "Login successful" in line:
            event_type = "auth_success"
        else:
            return None

        ts_match = TIMESTAMP_PATTERN.search(line)
        ip_match = IP_PATTERN.search(line)
        user_match = USER_PATTERN.search(line)

        timestamp_str = datetime.now(timezone.utc).isoformat()
        if ts_match:
            try:
                dt = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                timestamp_str = dt.isoformat()
            except Exception:
                pass

        source_ip = ip_match.group(1) if ip_match else None
        username = user_match.group(1) if user_match else None

        return {
            "event_type": event_type,
            "username": username,
            "source": "auth_collector",
            "source_ip": source_ip,
            "event_data": {"raw_line": line},
            "timestamp": timestamp_str
        }

    def collect(self) -> List[Dict[str, Any]]:
        if not self.enabled or not self.log_path.exists():
            return []

        events = []
        try:
            current_size = self.log_path.stat().st_size
            if current_size < self._offset:
                self._offset = 0  # Log rotation / truncation reset

            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                lines = f.readlines()
                self._offset = f.tell()

            for line in lines:
                parsed = self.parse_line(line)
                if parsed:
                    events.append(parsed)
        except Exception:
            pass

        return events

