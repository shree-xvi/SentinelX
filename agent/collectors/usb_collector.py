import ctypes
import getpass
import os
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Set
import psutil
from agent.collectors.base import BaseCollector


class USBCollector(BaseCollector):
    name = "usb"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._known_drives: Set[str] = set()
        self._initialized = False

    def _is_removable(self, mountpoint: str, opts: str) -> bool:
        if sys.platform == "win32":
            try:
                # DRIVE_REMOVABLE = 2
                drive_letter = mountpoint[:3] if len(mountpoint) >= 3 else mountpoint
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_letter)
                return drive_type == 2
            except Exception:
                return "removable" in opts.lower()
        else:
            return "removable" in opts.lower() or "/media/" in mountpoint or "/mnt/" in mountpoint

    def collect(self) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []

        events = []
        current_removable: Set[str] = set()
        drive_details: Dict[str, Dict[str, Any]] = {}

        try:
            partitions = psutil.disk_partitions(all=True)
            for part in partitions:
                if self._is_removable(part.mountpoint, part.opts):
                    current_removable.add(part.mountpoint)
                    drive_details[part.mountpoint] = {
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "opts": part.opts
                    }
        except Exception:
            pass

        if not self._initialized:
            self._known_drives = current_removable
            self._initialized = True
            return []

        # Detect newly plugged USB drive
        new_drives = current_removable - self._known_drives
        now = datetime.now(timezone.utc).isoformat()
        current_user = getpass.getuser()

        for drive in new_drives:
            details = drive_details.get(drive, {})
            events.append({
                "event_type": "usb_mount",
                "username": current_user,
                "source": "usb_collector",
                "source_ip": "127.0.0.1",
                "event_data": {
                    "device_id": details.get("device", drive),
                    "volume_name": drive,
                    "mountpoint": drive,
                    "fstype": details.get("fstype", ""),
                    "action": "mounted"
                },
                "timestamp": now
            })

        self._known_drives = current_removable
        return events

