import getpass
from datetime import datetime, timezone
from typing import List, Dict, Any, Set
import psutil
from agent.collectors.base import BaseCollector

LOOPBACK_IPS = {"127.0.0.1", "::1", "0.0.0.0"}


class NetworkCollector(BaseCollector):
    name = "network"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._known_connections: Set[str] = set()
        self._initialized = False

    def collect(self) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []

        events = []
        current_conns: Set[str] = set()
        now = datetime.now(timezone.utc).isoformat()
        current_user = getpass.getuser()

        try:
            conns = psutil.net_connections(kind="inet")
            for conn in conns:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                    if remote_ip in LOOPBACK_IPS:
                        continue

                    conn_key = f"{remote_ip}:{remote_port}"
                    current_conns.add(conn_key)

                    if self._initialized and conn_key not in self._known_connections:
                        events.append({
                            "event_type": "network_connection",
                            "username": current_user,
                            "source": "network_collector",
                            "source_ip": "127.0.0.1",
                            "event_data": {
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "local_port": conn.laddr.port if conn.laddr else None,
                                "pid": conn.pid
                            },
                            "timestamp": now
                        })
        except (psutil.AccessDenied, PermissionError):
            pass

        if not self._initialized:
            self._known_connections = current_conns
            self._initialized = True
            return []

        self._known_connections = current_conns
        return events[:50]

