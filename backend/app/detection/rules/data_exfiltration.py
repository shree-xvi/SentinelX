from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class DataExfiltrationRule(DetectionRule):
    rule_type = "DATA_EXFILTRATION"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        byte_threshold = int(config.get("byte_threshold", 50 * 1024 * 1024))  # 50 MB default
        count_threshold = int(config.get("count_threshold", 20))               # 20 files default
        window_minutes = int(config.get("window_minutes", 15))
        window = timedelta(minutes=window_minutes)

        exfil_events_by_user: Dict[str, List[Dict[str, Any]]] = {}

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in (
                "file_copy", "file_download", "file_export",
                "cloud_upload", "usb_copy", "data_transfer"
            ):
                continue

            user = event.get("username") or event.get("employee_id") or "unknown"
            ts = event.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if not ts:
                continue

            data = event.get("data") or event.get("event_data") or {}
            bytes_size = int(data.get("bytes") or data.get("size") or data.get("file_size") or 0)

            exfil_events_by_user.setdefault(user, []).append({
                "timestamp": ts,
                "bytes": bytes_size,
                "filename": data.get("filename") or data.get("filepath") or "unnamed_file",
                "destination": data.get("destination") or data.get("target") or "external",
                "source_ip": event.get("source_ip"),
                "employee_id": event.get("employee_id"),
            })

        alerts = []
        for user, user_events in exfil_events_by_user.items():
            user_events.sort(key=lambda x: x["timestamp"])

            for i in range(len(user_events)):
                start_time = user_events[i]["timestamp"]
                in_window = [e for e in user_events[i:] if (e["timestamp"] - start_time) <= window]

                total_bytes = sum(e["bytes"] for e in in_window)
                total_files = len(in_window)

                if (total_bytes >= byte_threshold and byte_threshold > 0) or (total_files >= count_threshold):
                    sample_files = [e["filename"] for e in in_window[:5]]
                    alerts.append({
                        "alert_type": self.rule_type,
                        "severity": config.get("severity", self.default_severity),
                        "source_ip": in_window[-1]["source_ip"],
                        "employee_id": in_window[-1]["employee_id"],
                        "evidence": {
                            "rule": self.rule_type,
                            "username": user,
                            "total_files": total_files,
                            "total_bytes": total_bytes,
                            "total_mb": round(total_bytes / (1024 * 1024), 2),
                            "window_minutes": window_minutes,
                            "sample_files": sample_files,
                            "destinations": list(set(e["destination"] for e in in_window)),
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })
                    break  # Alert generated for this user in this window

        return alerts

