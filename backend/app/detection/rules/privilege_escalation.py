from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class PrivilegeEscalationRule(DetectionRule):
    rule_type = "PRIVILEGE_ESCALATION"
    default_severity = "CRITICAL"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        approved_admins = set(config.get("approved_admin_users", []))
        alerts = []

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in (
                "privilege_escalation", "sudo_exec", "admin_role_assigned",
                "group_added_admin", "token_elevation", "runas_admin"
            ):
                continue

            user = event.get("username") or event.get("employee_id") or "unknown"
            if user in approved_admins:
                continue

            ts = event.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if not ts:
                continue

            data = event.get("data") or event.get("event_data") or {}
            target_role = data.get("target_role") or data.get("elevated_to") or "Administrator"
            command = data.get("command") or data.get("process") or "N/A"

            alerts.append({
                "alert_type": self.rule_type,
                "severity": config.get("severity", self.default_severity),
                "source_ip": event.get("source_ip"),
                "employee_id": event.get("employee_id"),
                "evidence": {
                    "rule": self.rule_type,
                    "username": user,
                    "target_role": target_role,
                    "command": command,
                    "event_type": etype,
                    "details": data.get("details", "User invoked administrative privilege elevation"),
                    "timestamp": ts.isoformat(),
                },
                "detected_at": datetime.now(timezone.utc)
            })

        return alerts

