
import sys
import unittest
from pathlib import Path
from datetime import datetime, timedelta


# Add the src directory to Python's module search path
SRC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC_DIR))

from detection.brute_force import detect_brute_force


class TestBruteForceDetection(unittest.TestCase):

    def test_detects_five_attempts_within_five_minutes(self):
        """Five attempts within five minutes should trigger an alert."""
        start = datetime(2026, 10, 2, 10, 0, 0)
        timestamps = [
            start + timedelta(seconds=i * 30)
            for i in range(5)
        ]

        result = detect_brute_force(timestamps)

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "BRUTE_FORCE")
        self.assertEqual(result["severity"], "HIGH")
        self.assertGreaterEqual(result["attempts"], 5)

    def test_no_alert_when_attempts_are_spread_out(self):
        """Attempts spread over more than five minutes should not alert."""
        start = datetime(2026, 10, 2, 10, 0, 0)
        timestamps = [
            start + timedelta(minutes=i * 10)
            for i in range(5)
        ]

        result = detect_brute_force(timestamps)

        self.assertIsNone(result)

    def test_no_alert_with_fewer_than_five_attempts(self):
        """Four attempts should not trigger an alert."""
        start = datetime(2026, 10, 2, 10, 0, 0)
        timestamps = [
            start + timedelta(seconds=i * 30)
            for i in range(4)
        ]

        result = detect_brute_force(timestamps)

        self.assertIsNone(result)

    def test_attempts_exactly_five_minutes_apart(self):
        """Five attempts spanning exactly five minutes should alert."""
        start = datetime(2026, 10, 2, 10, 0, 0)
        timestamps = [
            start + timedelta(minutes=i * 1.25)
            for i in range(5)
        ]

        result = detect_brute_force(timestamps)

        self.assertIsNotNone(result)

    def test_empty_timestamps(self):
        """An empty list should not trigger an alert."""
        result = detect_brute_force([])

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
