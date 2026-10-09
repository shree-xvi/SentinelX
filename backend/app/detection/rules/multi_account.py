from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class MultiAccountRule(DetectionRule):
    rule_type = "MULTI_ACCOUNT_FAILURES"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        min_distinct_users = int(config.get("min_distinct_users", 3))
        window_minutes = int(config.get("window_minutes", 5))
        window_seconds = window_minutes * 60

        failures_by_ip: Dict[str, List[Dict[str, Any]]] = {}

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype in ("failure", "auth_failure", "login_failed"):
                ip = event.get("source_ip")
                username = event.get("username")
                ts = event.get("timestamp")
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))

                if ip and username and ts:
                    failures_by_ip.setdefault(ip, []).append({
                        "timestamp": ts,
                        "username": username,
                        "employee_id": event.get("employee_id"),
                    })

        alerts = []
        for ip, failures in failures_by_ip.items():
            failures.sort(key=lambda x: x["timestamp"])

            for start_idx, first_fail in enumerate(failures):
                window_start = first_fail["timestamp"]
                distinct_users = set()
                matching_events = []

                for fail in failures[start_idx:]:
                    diff = (fail["timestamp"] - window_start).total_seconds()
                    if diff > window_seconds:
                        break
                    distinct_users.add(fail["username"])
                    matching_events.append(fail)

                    if len(distinct_users) >= min_distinct_users:
                        alerts.append({
                            "alert_type": self.rule_type,
                            "severity": config.get("severity", self.default_severity),
                            "source_ip": ip,
                            "employee_id": fail.get("employee_id"),
                            "evidence": {
                                "rule": self.rule_type,
                                "distinct_users": list(distinct_users),
                                "distinct_user_count": len(distinct_users),
                                "window_minutes": window_minutes,
                                "failures_count": len(matching_events),
                            },
                            "detected_at": datetime.now(timezone.utc)
                        })
                        break
                if alerts and alerts[-1].get("source_ip") == ip:
                    break

        return alerts

