from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule


DEFAULT_JOB_DOMAINS = [
    "indeed.com", "linkedin.com/jobs", "glassdoor.com", "monster.com",
    "dice.com", "ziprecruiter.com", "hired.com", "wellfound.com",
    "resume.io", "myperfectresume.com", "novoresume.com"
]


class FlightRiskRule(DetectionRule):
    rule_type = "FLIGHT_RISK_SIGNALS"
    default_severity = "MEDIUM"

    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        job_domains = [d.lower() for d in (config.get("job_domains") or DEFAULT_JOB_DOMAINS)]
        alerts = []
        seen = set()

        for event in events:
            etype = str(event.get("event_type", "")).lower()
            if etype not in ("web_visit", "dns_query", "http_request", "app_activity"):
                continue

            data = event.get("data") or event.get("event_data") or {}
            url = str(data.get("url") or data.get("domain") or data.get("host") or "").lower()

            matched_site = None
            for jdom in job_domains:
                if jdom in url:
                    matched_site = jdom
                    break

            if matched_site:
                user = event.get("username") or event.get("employee_id") or "unknown"
                ts = event.get("timestamp")
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if not ts:
                    continue

                dedup_key = f"{user}_{matched_site}_{ts.strftime('%Y%m%d%H')}"
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
                            "job_service": matched_site,
                            "url": data.get("url") or data.get("domain"),
                            "indicator": "Employee visited job board or resume building portal during work hours",
                            "timestamp": ts.isoformat(),
                        },
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts

