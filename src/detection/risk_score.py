"""
SentinelX risk scoring engine.

Converts alert evidence into a 0-100 risk score
and assigns a corresponding risk level.

Risk level thresholds are loaded from the
project configuration file.
"""

from config.config_loader import get_risk_config


VALID_RISK_LEVELS = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


DEFAULT_MEDIUM_THRESHOLD = 30
DEFAULT_HIGH_THRESHOLD = 60
DEFAULT_CRITICAL_THRESHOLD = 80


def calculate_risk_score(alert):
    """
    Calculate a risk score between 0 and 100.

    The score is based on evidence contained in the alert.
    """

    if not isinstance(alert, dict):
        return 0

    score = 0

    severity = str(
        alert.get("severity", "")
    ).upper()

    alert_type = str(
        alert.get("type", "")
    ).upper()

    attempts = alert.get(
        "attempts",
        0,
    )

    try:
        attempts = int(attempts)
    except (TypeError, ValueError):
        attempts = 0

    # -------------------------------------------------
    # Base score from alert severity
    # -------------------------------------------------

    severity_scores = {
        "LOW": 10,
        "MEDIUM": 30,
        "HIGH": 50,
        "CRITICAL": 70,
    }

    score += severity_scores.get(
        severity,
        0,
    )

    # -------------------------------------------------
    # Detection type
    # -------------------------------------------------

    detection_scores = {
        "BRUTE_FORCE": 15,
        "SUSPICIOUS_LOGIN": 15,
        "MULTI_ACCOUNT": 20,
    }

    score += detection_scores.get(
        alert_type,
        0,
    )

    # -------------------------------------------------
    # Failed authentication attempts
    # -------------------------------------------------

    if attempts >= 10:
        score += 20

    elif attempts >= 5:
        score += 15

    elif attempts >= 3:
        score += 10

    elif attempts > 0:
        score += 5

    # -------------------------------------------------
    # Suspicious / high-risk indicators
    # -------------------------------------------------

    if alert.get("suspicious") is True:
        score += 10

    if alert.get("multiple_accounts") is True:
        score += 10

    # -------------------------------------------------
    # Keep score within 0-100
    # -------------------------------------------------

    return min(
        max(score, 0),
        100,
    )


def get_risk_level(score):
    """
    Convert a numerical risk score into a risk level.

    Thresholds are loaded from config/sentinelx.json.
    """

    try:
        score = int(score)
    except (TypeError, ValueError):
        return "LOW"

    config = get_risk_config()

    medium_threshold = config.get(
        "medium_threshold",
        DEFAULT_MEDIUM_THRESHOLD,
    )

    high_threshold = config.get(
        "high_threshold",
        DEFAULT_HIGH_THRESHOLD,
    )

    critical_threshold = config.get(
        "critical_threshold",
        DEFAULT_CRITICAL_THRESHOLD,
    )

    try:
        medium_threshold = int(medium_threshold)
    except (TypeError, ValueError):
        medium_threshold = DEFAULT_MEDIUM_THRESHOLD

    try:
        high_threshold = int(high_threshold)
    except (TypeError, ValueError):
        high_threshold = DEFAULT_HIGH_THRESHOLD

    try:
        critical_threshold = int(critical_threshold)
    except (TypeError, ValueError):
        critical_threshold = DEFAULT_CRITICAL_THRESHOLD

    if score >= critical_threshold:
        return "CRITICAL"

    if score >= high_threshold:
        return "HIGH"

    if score >= medium_threshold:
        return "MEDIUM"

    return "LOW"


def calculate_risk(alert):
    """
    Calculate both the numerical score and risk level.

    Returns:

        {
            "score": 85,
            "level": "CRITICAL"
        }
    """

    score = calculate_risk_score(
        alert
    )

    return {
        "score": score,
        "level": get_risk_level(score),
    }