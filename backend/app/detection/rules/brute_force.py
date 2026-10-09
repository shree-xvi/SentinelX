from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class BruteForceRule(DetectionRule):
    rule_type = "BRUTE_FORCE"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        threshold = int(config.get("threshold", 5))
        window_minutes = int(config.get("window_minutes", 5))
        window = timedelta(minutes=window_minutes)

        # Filter failed auth events
        failures_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype in ("failure", "auth_failure", "login_failed"):
                ip = event.get("source_ip") or "unknown"
                ts = event.get("timestamp")
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if ts:
                    failures_by_ip.setdefault(ip, []).append({
                        "timestamp": ts,
                        "username": event.get("username"),
                        "employee_id": event.get("employee_id"),
                    })

        alerts = []
        for ip, fail_list in failures_by_ip.items():
            fail_list.sort(key=lambda x: x["timestamp"])
            for i in range(len(fail_list)):
                start_time = fail_list[i]["timestamp"]
                in_window = [f for f in fail_list[i:] if (f["timestamp"] - start_time) <= window]

                if len(in_window) >= threshold:
                    alerts.append({
                        "alert_type": self.rule_type,
                        "severity": config.get("severity", self.default_severity),
                        "source_ip": ip if ip != "unknown" else None,
                        "employee_id": in_window[-1].get("employee_id"),
                        "evidence": {
                            "rule": self.rule_type,
                            "attempts": len(in_window),
                            "threshold": threshold,
                            "window_minutes": window_minutes,
                            "target_users": list(set(f["username"] for f in in_window if f.get("username"))),
                            "window_start": start_time.isoformat(),
                            "window_end": in_window[-1]["timestamp"].isoformat(),
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })
                    break  # Alert generated for this IP
        return alerts

