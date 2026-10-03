import json
import tempfile
import unittest
from pathlib import Path

from utils.alert_report import (
    load_alerts,
    generate_alert_summary,
)


class TestAlertReport(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.alerts_file = Path(self.temp_dir.name) / "alerts.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_alerts(self):
        sample_alerts = [
            {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": "192.168.1.20",
            }
        ]

        self.alerts_file.write_text(
            json.dumps(sample_alerts),
            encoding="utf-8",
        )

        self.assertEqual(load_alerts(self.alerts_file), sample_alerts)

    def test_missing_file_returns_empty_list(self):
        self.assertEqual(load_alerts(self.alerts_file), [])

    def test_invalid_json_raises_value_error(self):
        self.alerts_file.write_text("{invalid json", encoding="utf-8")

        with self.assertRaises(ValueError):
            load_alerts(self.alerts_file)

    def test_summary_counts_alerts(self):
        alerts = [
            {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": "192.168.1.20",
            },
            {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": "192.168.1.20",
            },
            {
                "type": "MULTI_ACCOUNT_FAILURES",
                "severity": "HIGH",
                "source_ip": "192.168.1.50",
            },
        ]

        summary = generate_alert_summary(alerts)

        self.assertEqual(summary["total_alerts"], 3)
        self.assertEqual(summary["by_severity"]["HIGH"], 3)
        self.assertEqual(summary["by_type"]["BRUTE_FORCE"], 2)
        self.assertEqual(summary["by_source_ip"]["192.168.1.20"], 2)

    def test_empty_summary(self):
        summary = generate_alert_summary([])

        self.assertEqual(summary["total_alerts"], 0)
        self.assertEqual(summary["by_severity"], {})
        self.assertEqual(summary["by_type"], {})
        self.assertEqual(summary["by_source_ip"], {})


if __name__ == "__main__":
    unittest.main()