from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


DEFAULT_SENSITIVE_PATTERNS = [
    "confidential", "payroll", "executive", "secret", "private_key",
    "password", "credentials", ".pem", ".key", ".kdbx", "salary",
    "q3_forecast", "source_code", "customer_data"
]


class AbnormalResourceAccessRule(DetectionRule):
    rule_type = "ABNORMAL_RESOURCE_ACCESS"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        patterns = config.get("sensitive_patterns") or DEFAULT_SENSITIVE_PATTERNS
        alerts = []
        seen = set()

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("file_access", "file_read", "file_open", "directory_browse", "resource_access"):
                continue

            data = event.get("data") or event.get("event_data") or {}
            filepath = str(data.get("filepath") or data.get("path") or data.get("resource") or "").lower()

            matched_pattern = None
            for pattern in patterns:
                if pattern.lower() in filepath:
                    matched_pattern = pattern
                    break

            if matched_pattern:
                user = event.get("username") or event.get("employee_id") or "unknown"
                ts = event.get("timestamp")
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if not ts:
                    continue

                dedup_key = f"{user}_{matched_pattern}_{ts.strftime('%Y%m%d%H')}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    alerts.append({
                        "alert_type": self.rule_type,
                        "severity": config.get("severity", self.default_severity),
                        "source_ip": event.get("source_ip"),
                        "employee_id": event.get("employee_id"),
                        "evidence": {
                            "rule": self.rule_type,
                            "username": user,
                            "filepath": data.get("filepath") or data.get("path"),
                            "matched_pattern": matched_pattern,
                            "action": data.get("action", "read"),
                            "timestamp": ts.isoformat(),
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts

