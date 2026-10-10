from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


DEFAULT_UNAPPROVED_DOMAINS = [
    "wetransfer.com", "mega.nz", "pastebin.com", "anonfiles.com",
    "sendspace.com", "mediafire.com", "file.io", "gofile.io",
    "torproject.org", "protonvpn.com", "nordvpn.com", "temp-mail.org"
]


class ShadowITRule(DetectionRule):
    rule_type = "SHADOW_IT_USAGE"
    default_severity = "MEDIUM"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        unapproved = [d.lower() for d in (config.get("unapproved_domains") or DEFAULT_UNAPPROVED_DOMAINS)]
        alerts = []
        seen = set()

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("dns_query", "http_request", "web_visit", "network_connection", "app_launch"):
                continue

            data = event.get("data") or event.get("event_data") or {}
            domain = str(data.get("domain") or data.get("host") or data.get("url") or data.get("app_name") or "").lower()

            matched = None
            for bad_domain in unapproved:
                if bad_domain in domain:
                    matched = bad_domain
                    break

            if matched:
                user = event.get("username") or event.get("employee_id") or "unknown"
                ts = event.get("timestamp")
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if not ts:
                    continue

                dedup_key = f"{user}_{matched}_{ts.strftime('%Y%m%d%H')}"
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
                            "domain": domain,
                            "matched_unapproved_service": matched,
                            "bytes_transferred": data.get("bytes", 0),
                            "timestamp": ts.isoformat(),
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts

