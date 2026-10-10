import getpass
from datetime import datetime, timezone
from typing import List, Dict, Any, Set
import psutil
from agent.collectors.base import BaseCollector

SUSPICIOUS_TOOLS = {
    "runas.exe", "psexec.exe", "wireshark.exe", "nmap.exe",
    "mimikatz.exe", "procdump.exe", "tcpdump", "nc", "netcat"
}


class ProcessCollector(BaseCollector):
    name = "process"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._known_pids: Set[int] = set()
        self._initialized = False

    def collect(self) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []

        events = []
        current_pids: Set[int] = set()
        now = datetime.now(timezone.utc).isoformat()
        current_user = getpass.getuser()

        for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
            try:
                pid = proc.info["pid"]
                current_pids.add(pid)

                if self._initialized and pid not in self._known_pids:
                    name = str(proc.info["name"] or "").lower()
                    cmdline = " ".join(proc.info["cmdline"] or [])
                    user = proc.info["username"] or current_user

                    # Check for elevated or suspicious tools
                    if name in SUSPICIOUS_TOOLS or "runas" in cmdline.lower():
                        events.append({
                            "event_type": "privilege_escalation",
                            "username": user,
                            "source": "process_collector",
                            "source_ip": "127.0.0.1",
                            "event_data": {
                                "process_name": proc.info["name"],
                                "pid": pid,
                                "command": cmdline,
                                "target_role": "elevated",
                                "action": "process_elevation"
                            },
                            "timestamp": now
                        })
                    else:
                        # Regular process launch
                        events.append({
                            "event_type": "process_launch",
                            "username": user,
                            "source": "process_collector",
                            "source_ip": "127.0.0.1",
                            "event_data": {
                                "process_name": proc.info["name"],
                                "pid": pid,
                                "command": cmdline[:300]
                            },
                            "timestamp": now
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not self._initialized:
            self._known_pids = current_pids
            self._initialized = True
            return []

        self._known_pids = current_pids
        # Return at most 50 process events per poll cycle to avoid flood
        return events[:50]

