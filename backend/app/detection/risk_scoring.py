from typing import Dict, Any, Tuple


DEFAULT_MEDIUM_THRESHOLD = 30
DEFAULT_HIGH_THRESHOLD = 60
DEFAULT_CRITICAL_THRESHOLD = 80


def calculate_risk_score(alert_data: Dict[str, Any], risk_config: Dict[str, Any] = None) -> float:
    """
    Calculate a normalized risk score between 0 and 100 based on alert evidence.
    """
    if not isinstance(alert_data, dict):
        return 0.0

    score = 0.0
    severity = str(alert_data.get("severity", "MEDIUM")).upper()
    alert_type = str(alert_data.get("alert_type", alert_data.get("type", ""))).upper()

    evidence = alert_data.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    attempts = alert_data.get("attempts", evidence.get("attempts", 0))
    try:
        attempts = int(attempts)
    except (TypeError, ValueError):
        attempts = 0

    # 1. Base score from severity
    severity_scores = {
        "LOW": 15.0,
        "MEDIUM": 35.0,
        "HIGH": 65.0,
        "CRITICAL": 85.0,
    }
    score += severity_scores.get(severity, 35.0)

    # 2. Type weights
    type_bonus = {
        "BRUTE_FORCE": 15.0,
        "SUSPICIOUS_LOGIN": 20.0,
        "SUSPICIOUS_LOGIN_AFTER_FAILURES": 20.0,
        "MULTI_ACCOUNT": 25.0,
        "MULTI_ACCOUNT_FAILURES": 25.0,
        "AFTER_HOURS_ACCESS": 15.0,
        "DATA_EXFILTRATION": 30.0,
        "IMPOSSIBLE_TRAVEL": 25.0,
        "PRIVILEGE_ESCALATION": 30.0,
        "MASS_FILE_OPERATIONS": 25.0,
        "USB_DEVICE_USAGE": 20.0,
        "ABNORMAL_RESOURCE_ACCESS": 25.0,
        "SHADOW_IT_USAGE": 15.0,
        "ANOMALOUS_EMAIL_ACTIVITY": 20.0,
        "FLIGHT_RISK_SIGNALS": 15.0,
    }
    score += type_bonus.get(alert_type, 10.0)

    # 3. Repeated attempts multiplier
    if attempts >= 10:
        score += 20.0
    elif attempts >= 5:
        score += 15.0
    elif attempts >= 3:
        score += 10.0

    # 4. Critical flags
    if alert_data.get("suspicious") or evidence.get("suspicious"):
        score += 10.0
    if alert_data.get("multiple_accounts") or evidence.get("multiple_accounts"):
        score += 15.0

    return float(min(max(round(score, 1), 0.0), 100.0))


def get_risk_level(score: float, risk_config: Dict[str, Any] = None) -> str:
    """Convert numerical risk score to risk level string."""
    cfg = risk_config or {}
    med = cfg.get("medium_threshold", DEFAULT_MEDIUM_THRESHOLD)
    high = cfg.get("high_threshold", DEFAULT_HIGH_THRESHOLD)
    crit = cfg.get("critical_threshold", DEFAULT_CRITICAL_THRESHOLD)

    if score >= crit:
        return "CRITICAL"
    if score >= high:
        return "HIGH"
    if score >= med:
        return "MEDIUM"
    return "LOW"


def evaluate_risk(alert_data: Dict[str, Any], risk_config: Dict[str, Any] = None) -> Tuple[float, str]:
    """Calculate both score and level."""
    score = calculate_risk_score(alert_data, risk_config)
    level = get_risk_level(score, risk_config)
    return score, level

