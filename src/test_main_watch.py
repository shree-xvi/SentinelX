
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO

from main import (
    read_new_events,
    run_watch,
    should_reset_log,
    get_file_identity,
)


VALID_LOG_LINE = (
    "2026-10-03 18:10:01 WARN "
    "Login failed user=testadmin ip=192.168.1.99"
)


class TestLiveMonitor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.log_file = self.root / "auth.log"
        self.log_file.write_text("", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_reads_newly_appended_complete_line(self):
        initial_offset = self.log_file.stat().st_size

        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(VALID_LOG_LINE + "\n")

        events, new_offset, pending = read_new_events(
            self.log_file, initial_offset
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "testadmin")
        self.assertEqual(events[0]["source_ip"], "192.168.1.99")
        self.assertEqual(events[0]["event_type"], "failure")
        self.assertEqual(pending, b"")
        self.assertEqual(new_offset, self.log_file.stat().st_size)

    def test_waits_for_incomplete_line_to_finish(self):
        with self.log_file.open("ab") as file:
            file.write(VALID_LOG_LINE.encode("utf-8"))

        events, offset, pending = read_new_events(self.log_file, 0)

        self.assertEqual(events, [])
        self.assertEqual(pending, VALID_LOG_LINE.encode("utf-8"))

        with self.log_file.open("ab") as file:
            file.write(b"\n")

        events, new_offset, pending = read_new_events(
            self.log_file, offset, pending
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "testadmin")
        self.assertEqual(pending, b"")
        self.assertEqual(new_offset, self.log_file.stat().st_size)

    def test_monitor_stops_cleanly_on_keyboard_interrupt(self):
        self.log_file.write_text(
            VALID_LOG_LINE + "\n",
            encoding="utf-8",
        )

        output = StringIO()

        with patch("main.time.sleep", side_effect=KeyboardInterrupt):
            with redirect_stdout(output):
                result = run_watch(self.log_file, poll_seconds=0.01)

        self.assertEqual(result, 0)
        self.assertIn("SENTINELX LIVE MONITOR", output.getvalue())
        self.assertIn("Live monitoring stopped", output.getvalue())

    def test_detects_truncated_log(self):
        self.log_file.write_text("some old log contents\n", encoding="utf-8")
        old_size = self.log_file.stat().st_size
        identity = get_file_identity(self.log_file)

        self.log_file.write_text("x\n", encoding="utf-8")
        new_size = self.log_file.stat().st_size
        new_identity = get_file_identity(self.log_file)

        self.assertLess(new_size, old_size)
        self.assertTrue(
            should_reset_log(
                new_size, old_size, new_identity, identity
            )
        )

    def test_detects_replaced_log_file(self):
        self.log_file.write_text("original log\n", encoding="utf-8")
        old_size = self.log_file.stat().st_size
        old_identity = get_file_identity(self.log_file)

        replacement = self.root / "replacement.log"
        replacement.write_text("replacement log with more data\n", encoding="utf-8")

        os.replace(replacement, self.log_file)

        new_size = self.log_file.stat().st_size
        new_identity = get_file_identity(self.log_file)

        self.assertNotEqual(old_identity, new_identity)
        self.assertTrue(
            should_reset_log(
                new_size, old_size, new_identity, old_identity
            )
        )


if __name__ == "__main__":
    unittest.main()
