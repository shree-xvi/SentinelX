import tempfile
import time
from pathlib import Path
from agent.collectors.auth_collector import AuthCollector
from agent.collectors.file_collector import FileCollector
from agent.collectors.usb_collector import USBCollector
from agent.collectors.process_collector import ProcessCollector
from agent.collectors.network_collector import NetworkCollector


def test_auth_collector_parsing():
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        f.write("2026-10-10 14:00:00 INFO Login successful user=admin ip=192.168.1.10\n")
        f.write("2026-10-10 14:01:00 WARN Login failed user=admin ip=192.168.1.20\n")
        f.flush()
        temp_path = Path(f.name)

    try:
        collector = AuthCollector({"enabled": True, "log_path": str(temp_path)})
        events = collector.collect()
        assert len(events) == 2

        assert events[0]["event_type"] == "auth_success"
        assert events[0]["username"] == "admin"
        assert events[0]["source_ip"] == "192.168.1.10"

        assert events[1]["event_type"] == "auth_failure"
        assert events[1]["username"] == "admin"
        assert events[1]["source_ip"] == "192.168.1.20"

        # Subsequent collect with no new lines should return empty
        events_2 = collector.collect()
        assert len(events_2) == 0
    finally:
        temp_path.unlink(missing_ok=True)


def test_file_collector_lifecycle():
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        collector = FileCollector({"enabled": True, "monitored_paths": [str(dir_path)]})

        # Initial collection sets baseline
        initial = collector.collect()
        assert len(initial) == 0

        # Create a file
        test_file = dir_path / "secret_document.txt"
        test_file.write_text("Confidential intellectual property.")
        time.sleep(0.05)

        events = collector.collect()
        assert len(events) >= 1
        assert any(e["event_type"] == "file_copy" and e["event_data"]["filename"] == "secret_document.txt" for e in events)

        # Delete the file
        test_file.unlink()
        events_del = collector.collect()
        assert any(e["event_type"] == "file_delete" for e in events_del)


def test_usb_collector_initialization():
    collector = USBCollector({"enabled": True})
    # First collection initializes known partitions baseline
    events = collector.collect()
    assert isinstance(events, list)


def test_process_collector():
    collector = ProcessCollector({"enabled": True})
    # First collect sets known PIDs baseline
    events = collector.collect()
    assert isinstance(events, list)


def test_network_collector():
    collector = NetworkCollector({"enabled": True})
    # First collect sets known connections baseline
    events = collector.collect()
    assert isinstance(events, list)

