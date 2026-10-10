from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


PERSONAL_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com", "icloud.com"]


class EmailAnomalyRule(DetectionRule):
    rule_type = "ANOMALOUS_EMAIL_ACTIVITY"
    default_severity = "HIGH"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        attachment_limit_bytes = int(config.get("attachment_limit_bytes", 10 * 1024 * 1024))  # 10 MB
        personal_domains = config.get("personal_domains") or PERSONAL_EMAIL_DOMAINS

        alerts = []

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("email_send", "email_forward", "email_outbound"):
                continue

            data = event.get("data") or event.get("event_data") or {}
            recipients = data.get("recipients") or []
            if isinstance(recipients, str):
                recipients = [recipients]

            bcc_list = data.get("bcc") or []
            if isinstance(bcc_list, str):
                bcc_list = [bcc_list]

            attachment_size = int(data.get("attachment_size_bytes") or data.get("attachment_size") or 0)
            subject = data.get("subject", "No subject")

            flags = []

            # Check personal domains in recipients/bcc
            personal_recipients = []
            for r in recipients + bcc_list:
                for pdom in personal_domains:
                    if f"@{pdom.lower()}" in r.lower():
                        personal_recipients.append(r)
                        break

            if personal_recipients:
                flags.append(f"Email sent to personal email addresses: {', '.join(personal_recipients[:3])}")

            if attachment_size >= attachment_limit_bytes:
                flags.append(f"Large attachment size: {round(attachment_size / (1024 * 1024), 1)} MB")

            if len(bcc_list) >= 10:
                flags.append(f"Mass BCC recipient count ({len(bcc_list)} addresses)")

            if flags:
                user = event.get("username") or event.get("employee_id") or "unknown"
                ts = event.get("timestamp")
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if not ts:
                    continue

                alerts.append({
                    "alert_type": self.rule_type,
                    "severity": config.get("severity", self.default_severity),
                    "source_ip": event.get("source_ip"),
                    "employee_id": event.get("employee_id"),
                    "evidence": {
                        "rule": self.rule_type,
                        "username": user,
                        "subject": subject,
                        "anomalies": flags,
                        "personal_recipients": personal_recipients,
                        "attachment_size_mb": round(attachment_size / (1024 * 1024), 2),
                        "timestamp": ts.isoformat(),
                    },
                    "detected_at": datetime.now(timezone.utc)
                })

        return alerts

