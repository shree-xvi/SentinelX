from abc import ABC, abstractmethod
from typing import List, Dict, Any


class BaseCollector(ABC):
    """Abstract base class for all endpoint telemetry collectors."""

    name: str = "base"

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", True))

    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """
        Poll and return a list of newly observed events formatted as:
        [
            {
                "event_type": str,
                "username": Optional[str],
                "source": str,
                "source_ip": Optional[str],
                "event_data": Dict[str, Any],
                "timestamp": str (ISO)
            }
        ]
        """
        pass

