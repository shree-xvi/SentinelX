from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


class USBDeviceUsageRule(DetectionRule):
    rule_type = "USB_DEVICE_USAGE"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        allowed_devices = set(config.get("allowed_device_ids", []))
        alerts = []
        seen_events = set()

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("usb_mount", "usb_insert", "usb_storage_connected", "usb_copy"):
                continue

            data = event.get("data") or event.get("event_data") or {}
            device_id = str(data.get("device_id") or data.get("serial_number") or data.get("vendor_id") or "generic_usb")

            if device_id in allowed_devices:
                continue

            user = event.get("username") or event.get("employee_id") or "unknown"
            ts = event.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if not ts:
                continue

            event_key = f"{user}_{device_id}_{ts.strftime('%Y%m%d%H%M')}"
            if event_key not in seen_events:
                seen_events.add(event_key)

                device_name = data.get("device_name") or data.get("product_name") or "Removable USB Storage"
                volume_name = data.get("volume_name") or data.get("drive_letter") or "Removable Disk"
                copied_files = data.get("files") or []

                alerts.append({
                    "alert_type": self.rule_type,
                    "severity": config.get("severity", self.default_severity),
                    "source_ip": event.get("source_ip"),
                    "employee_id": event.get("employee_id"),
                    "evidence": {
                        "rule": self.rule_type,
                        "username": user,
                        "device_id": device_id,
                        "device_name": device_name,
                        "volume_name": volume_name,
                        "files_copied": copied_files,
                        "event_type": etype,
                        "timestamp": ts.isoformat(),
                    },
                    "detected_at": datetime.now(timezone.utc)
                })

        return alerts

