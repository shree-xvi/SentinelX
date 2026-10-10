from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class SuspiciousLoginRule(DetectionRule):
    rule_type = "SUSPICIOUS_LOGIN_AFTER_FAILURES"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        min_failures = int(config.get("min_failures", 3))
        window_minutes = int(config.get("window_minutes", 5))
        window = timedelta(minutes=window_minutes)

        parsed_events = []
        for e in events:
            ts = e.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if ts:
                parsed_events.append({**e, "_ts": ts})

        parsed_events.sort(key=lambda x: x["_ts"])

        failures_by_ip: Dict[str, List[datetime]] = {}
        alerts = []

        for event in parsed_events:
            etype = str(event.get("event_type", "")).lower()
            ip = event.get("source_ip") or "unknown"
            ts = event["_ts"]

            if etype in ("failure", "auth_failure", "login_failed"):
                failures_by_ip.setdefault(ip, []).append(ts)
            elif etype in ("success", "auth_success", "login_successful"):
                recent_fails = [
                    f_time for f_time in failures_by_ip.get(ip, [])
                    if timedelta(0) <= (ts - f_time) <= window
                ]
                if len(recent_fails) >= min_failures:
                    alerts.append({
                        "alert_type": self.rule_type,
                        "severity": config.get("severity", self.default_severity),
                        "source_ip": ip if ip != "unknown" else None,
                        "employee_id": event.get("employee_id"),
                        "evidence": {
                            "rule": self.rule_type,
                            "failed_attempts": len(recent_fails),
                            "window_minutes": window_minutes,
                            "successful_user": event.get("username"),
                            "success_timestamp": ts.isoformat(),
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })
                    # Clear processed failures for this IP
                    failures_by_ip[ip] = []

        return alerts

