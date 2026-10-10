import getpass
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from agent.collectors.base import BaseCollector


class FileCollector(BaseCollector):
    name = "file"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.monitored_paths = [Path(p) for p in self.config.get("monitored_paths", [])]
        self._file_state: Dict[str, float] = {}  # filepath -> mtime
        self._initialized = False

    def collect(self) -> List[Dict[str, Any]]:
        if not self.enabled or not self.monitored_paths:
            return []

        events = []
        current_user = getpass.getuser()
        current_state: Dict[str, float] = {}

        for root_path in self.monitored_paths:
            if not root_path.exists():
                continue

            try:
                if root_path.is_file():
                    stat = root_path.stat()
                    current_state[str(root_path)] = stat.st_mtime
                else:
                    for entry in root_path.rglob("*"):
                        if entry.is_file():
                            try:
                                stat = entry.stat()
                                current_state[str(entry)] = stat.st_mtime
                            except Exception:
                                pass
            except Exception:
                pass

        now = datetime.now(timezone.utc).isoformat()

        # If first run, initialize state without generating flood of events
        if not self._initialized:
            self._file_state = current_state
            self._initialized = True
            return []

        # Detect new or modified files
        for path_str, mtime in current_state.items():
            if path_str not in self._file_state:
                # Newly created / copied file
                p = Path(path_str)
                size = p.stat().st_size if p.exists() else 0
                events.append({
                    "event_type": "file_copy",
                    "username": current_user,
                    "source": "file_collector",
                    "source_ip": "127.0.0.1",
                    "event_data": {
                        "filepath": path_str,
                        "filename": p.name,
                        "bytes": size,
                        "action": "create"
                    },
                    "timestamp": now
                })
            elif mtime > self._file_state[path_str]:
                # Modified file
                p = Path(path_str)
                size = p.stat().st_size if p.exists() else 0
                events.append({
                    "event_type": "file_modify",
                    "username": current_user,
                    "source": "file_collector",
                    "source_ip": "127.0.0.1",
                    "event_data": {
                        "filepath": path_str,
                        "filename": p.name,
                        "bytes": size,
                        "action": "modify"
                    },
                    "timestamp": now
                })

        # Detect deleted files
        for path_str in self._file_state:
            if path_str not in current_state:
                events.append({
                    "event_type": "file_delete",
                    "username": current_user,
                    "source": "file_collector",
                    "source_ip": "127.0.0.1",
                    "event_data": {
                        "filepath": path_str,
                        "action": "delete"
                    },
                    "timestamp": now
                })

        self._file_state = current_state
        return events

