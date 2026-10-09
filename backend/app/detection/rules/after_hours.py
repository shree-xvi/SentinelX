from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class AfterHoursAccessRule(DetectionRule):
    rule_type = "AFTER_HOURS_ACCESS"
    default_severity = "MEDIUM"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        start_hour = int(config.get("business_hours_start", 9))
        end_hour = int(config.get("business_hours_end", 18))
        allow_weekends = bool(config.get("allow_weekends", False))

        alerts = []
        seen_keys = set()

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("auth_success", "login_successful", "vpn_connect", "system_access", "file_access"):
                continue

            ts = event.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if not ts:
                continue

            is_weekend = ts.weekday() >= 5  # Saturday = 5, Sunday = 6
            is_outside_hours = (ts.hour < start_hour or ts.hour >= end_hour)

            if is_outside_hours or (is_weekend and not allow_weekends):
                user = event.get("username") or "unknown"
                emp_id = event.get("employee_id")
                dedup_key = f"{emp_id or user}_{ts.date()}_{ts.hour}"

                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    reason = []
                    if is_outside_hours:
                        reason.append(f"Activity at {ts.strftime('%H:%M')} is outside standard business hours ({start_hour:02d}:00 - {end_hour:02d}:00)")
                    if is_weekend and not allow_weekends:
                        reason.append(f"Activity on weekend ({ts.strftime('%A')})")

                    alerts.append({
                        "alert_type": self.rule_type,
                        "severity": config.get("severity", self.default_severity),
                        "source_ip": event.get("source_ip"),
                        "employee_id": emp_id,
                        "evidence": {
                            "rule": self.rule_type,
                            "timestamp": ts.isoformat(),
                            "username": user,
                            "reasons": reason,
                            "event_type": etype,
                            "business_hours": f"{start_hour:02d}:00-{end_hour:02d}:00",
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts

