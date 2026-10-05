import unittest

from detection.risk_score import (
    calculate_risk,
    calculate_risk_score,
    get_risk_level,
)


class TestRiskScore(unittest.TestCase):

    def test_invalid_alert_returns_zero(self):
        self.assertEqual(
            calculate_risk_score(None),
            0,
        )

    def test_high_brute_force_with_five_attempts(self):
        alert = {
            "severity": "HIGH",
            "type": "BRUTE_FORCE",
            "attempts": 5,
        }

        self.assertEqual(
            calculate_risk_score(alert),
            80,
        )

    def test_critical_score(self):
        self.assertEqual(
            get_risk_level(80),
            "CRITICAL",
        )

    def test_high_score(self):
        self.assertEqual(
            get_risk_level(60),
            "HIGH",
        )

    def test_medium_score(self):
        self.assertEqual(
            get_risk_level(30),
            "MEDIUM",
        )

    def test_low_score(self):
        self.assertEqual(
            get_risk_level(29),
            "LOW",
        )

    def test_ten_or_more_attempts(self):
        alert = {
            "severity": "HIGH",
            "type": "BRUTE_FORCE",
            "attempts": 10,
        }

        score = calculate_risk_score(alert)

        self.assertEqual(
            score,
            85,
        )

    def test_suspicious_login(self):
        alert = {
            "severity": "MEDIUM",
            "type": "SUSPICIOUS_LOGIN",
            "attempts": 3,
        }

        score = calculate_risk_score(alert)

        self.assertEqual(
            score,
            55,
        )

    def test_multi_account_detection(self):
        alert = {
            "severity": "HIGH",
            "type": "MULTI_ACCOUNT",
            "attempts": 5,
        }

        score = calculate_risk_score(alert)

        self.assertEqual(
            score,
            85,
        )

    def test_score_never_exceeds_100(self):
        alert = {
            "severity": "CRITICAL",
            "type": "MULTI_ACCOUNT",
            "attempts": 100,
            "suspicious": True,
            "multiple_accounts": True,
        }

        score = calculate_risk_score(alert)

        self.assertLessEqual(
            score,
            100,
        )

    def test_calculate_risk_returns_score_and_level(self):
        alert = {
            "severity": "HIGH",
            "type": "BRUTE_FORCE",
            "attempts": 5,
        }

        result = calculate_risk(alert)

        self.assertEqual(
            result["score"],
            80,
        )

        self.assertEqual(
            result["level"],
            "CRITICAL",
        )


if __name__ == "__main__":
    unittest.main()