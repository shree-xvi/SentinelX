import hashlib
import json
from typing import List, Dict, Any
from backend.app.detection.base import DetectionRule
from backend.app.detection.rules.brute_force import BruteForceRule
from backend.app.detection.rules.suspicious_login import SuspiciousLoginRule
from backend.app.detection.rules.multi_account import MultiAccountRule
from backend.app.detection.rules.after_hours import AfterHoursAccessRule
from backend.app.detection.rules.impossible_travel import ImpossibleTravelRule
from backend.app.detection.rules.data_exfiltration import DataExfiltrationRule
from backend.app.detection.rules.mass_file_ops import MassFileOperationsRule
from backend.app.detection.rules.usb_usage import USBDeviceUsageRule
from backend.app.detection.rules.privilege_escalation import PrivilegeEscalationRule
from backend.app.detection.rules.abnormal_access import AbnormalResourceAccessRule
from backend.app.detection.rules.shadow_it import ShadowITRule
from backend.app.detection.rules.email_anomaly import EmailAnomalyRule
from backend.app.detection.rules.flight_risk import FlightRiskRule
from backend.app.detection.risk_scoring import evaluate_risk


class DetectionEngine:
    def __init__(self):
        self._rules: Dict[str, DetectionRule] = {}
        # Core Auth Rules
        self.register_rule(BruteForceRule())
        self.register_rule(SuspiciousLoginRule())
        self.register_rule(MultiAccountRule())
        # Insider Threat Rules
        self.register_rule(AfterHoursAccessRule())
        self.register_rule(ImpossibleTravelRule())
        self.register_rule(DataExfiltrationRule())
        self.register_rule(MassFileOperationsRule())
        self.register_rule(USBDeviceUsageRule())
        self.register_rule(PrivilegeEscalationRule())
        self.register_rule(AbnormalResourceAccessRule())
        self.register_rule(ShadowITRule())
        self.register_rule(EmailAnomalyRule())
        self.register_rule(FlightRiskRule())

    def register_rule(self, rule: DetectionRule):
        self._rules[rule.rule_type] = rule

    @staticmethod
    def compute_fingerprint(alert: Dict[str, Any]) -> str:
        """Stable SHA256 fingerprint for alert deduplication."""
        canon = {
            "alert_type": alert.get("alert_type"),
            "source_ip": alert.get("source_ip"),
            "employee_id": alert.get("employee_id"),
            "rule": alert.get("evidence", {}).get("rule", alert.get("alert_type")),
        }
        raw = json.dumps(canon, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def run(
        self,
        events: List[Dict[str, Any]],
        policies: List[Dict[str, Any]] = None,
        risk_config: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Run all applicable detection rules against given events.
        """
        policies_by_type = {}
        if policies:
            for p in policies:
                policies_by_type[p.get("rule_type")] = p

        generated_alerts = []

        for rule_type, rule in self._rules.items():
            # Check if policy exists and is enabled
            policy = policies_by_type.get(rule_type)
            if policy and not policy.get("enabled", True):
                continue  # Rule disabled by tenant

            conditions = policy.get("conditions", {}) if policy else {}
            rule_alerts = rule.evaluate(events, conditions)

            for alert in rule_alerts:
                # Calculate risk score & level
                score, level = evaluate_risk(alert, risk_config)
                alert["risk_score"] = score
                alert["risk_level"] = level
                alert["fingerprint"] = self.compute_fingerprint(alert)
                generated_alerts.append(alert)

        return generated_alerts


engine = DetectionEngine()

