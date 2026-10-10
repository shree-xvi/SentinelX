from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime


class DetectionRule(ABC):
    """Base class for all SentinelX detection rules."""

    rule_type: str = "BASE_RULE"
    default_severity: str = "MEDIUM"

    @abstractmethod
    def evaluate(self, events: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate a sequence of events against this detection rule.

        Returns a list of alert dictionaries:
        [
            {
                "alert_type": str,
                "severity": str,
                "source_ip": Optional[str],
                "employee_id": Optional[str],
                "evidence": Dict[str, Any],
                "detected_at": datetime
            }
        ]
        """
        pass

