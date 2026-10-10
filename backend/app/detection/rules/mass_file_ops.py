from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class MassFileOperationsRule(DetectionRule):
    rule_type = "MASS_FILE_OPERATIONS"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        threshold = int(config.get("threshold", 30))
        window_minutes = int(config.get("window_minutes", 10))
        window = timedelta(minutes=window_minutes)

        ops_by_user: Dict[str, List[Dict[str, Any]]] = {}

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("file_delete", "file_rename", "file_modify", "file_copy", "bulk_delete"):
                continue

            user = event.get("username") or event.get("employee_id") or "unknown"
            ts = event.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if not ts:
                continue

            data = event.get("data") or event.get("event_data") or {}
            ops_by_user.setdefault(user, []).append({
                "timestamp": ts,
                "op_type": etype,
                "path": data.get("filepath") or data.get("path") or "unknown_path",
                "source_ip": event.get("source_ip"),
                "employee_id": event.get("employee_id"),
            })

        alerts = []
        for user, op_list in ops_by_user.items():
            op_list.sort(key=lambda x: x["timestamp"])

            for i in range(len(op_list)):
                start_time = op_list[i]["timestamp"]
                in_window = [op for op in op_list[i:] if (op["timestamp"] - start_time) <= window]

                if len(in_window) >= threshold:
                    op_breakdown = {}
                    for op in in_window:
                        op_breakdown[op["op_type"]] = op_breakdown.get(op["op_type"], 0) + 1

                    alerts.append({
                        "alert_type": self.rule_type,
                        "severity": config.get("severity", self.default_severity),
                        "source_ip": in_window[-1]["source_ip"],
                        "employee_id": in_window[-1]["employee_id"],
                        "evidence": {
                            "rule": self.rule_type,
                            "username": user,
                            "total_operations": len(in_window),
                            "threshold": threshold,
                            "window_minutes": window_minutes,
                            "operation_breakdown": op_breakdown,
                            "sample_paths": [op["path"] for op in in_window[:5]],
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })
                    break

        return alerts

