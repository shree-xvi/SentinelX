from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from backend.app.models.risk_profile import RiskProfile
from backend.app.models.employee import Employee


def calculate_employee_baseline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Construct a behavioral baseline from historical user events.
    Includes:
    - 24-hour activity distribution histogram
    - Known source IPs
    - Average daily activity volume
    - Common event types
    """
    if not events:
        return {
            "hourly_distribution": [0] * 24,
            "known_ips": [],
            "daily_avg_events": 0.0,
            "event_counts": {},
            "total_events": 0
        }

    hourly_counts = [0] * 24
    ip_counter = Counter()
    days_seen = set()
    event_type_counter = Counter()

    for ev in events:
        ts = ev.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if ts:
            hourly_counts[ts.hour] += 1
            days_seen.add(ts.date())

        ip = ev.get("source_ip")
        if ip:
            ip_counter[ip] += 1

        etype = ev.get("event_type")
        if etype:
            event_type_counter[etype] += 1

    total_days = max(1, len(days_seen))
    total_events = len(events)
    daily_avg = round(total_events / float(total_days), 1)

    return {
        "hourly_distribution": hourly_counts,
        "known_ips": [ip for ip, _ in ip_counter.most_common(5)],
        "daily_avg_events": daily_avg,
        "event_counts": dict(event_type_counter),
        "total_events": total_events
    }


def detect_behavioral_anomaly(current_event: Dict[str, Any], baseline: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Score the deviation of a single event from the employee's historical baseline.
    Returns: (anomaly_score_0_to_100, list_of_reasons)
    """
    if not baseline or baseline.get("total_events", 0) < 5:
        # Not enough historical baseline to reliably flag anomalies
        return 0.0, []

    score = 0.0
    reasons = []

    ts = current_event.get("timestamp")
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))

    # 1. Hour anomaly
    if ts:
        hour = ts.hour
        hourly_dist = baseline.get("hourly_distribution", [0] * 24)
        total_hist = baseline.get("total_events", 1)
        hour_fraction = hourly_dist[hour] / float(total_hist)

        if hour_fraction == 0.0:
            score += 35.0
            reasons.append(f"Activity at {hour:02d}:00 never observed in historical baseline")
        elif hour_fraction < 0.02:
            score += 15.0
            reasons.append(f"Unusually low historical activity at {hour:02d}:00 (<2% baseline)")

    # 2. IP anomaly
    ip = current_event.get("source_ip")
    known_ips = baseline.get("known_ips", [])
    if ip and known_ips and ip not in known_ips:
        score += 25.0
        reasons.append(f"Access from unrecognised source IP: {ip}")

    # 3. Rare event type anomaly
    etype = current_event.get("event_type")
    event_counts = baseline.get("event_counts", {})
    if etype and etype not in event_counts:
        score += 20.0
        reasons.append(f"First-time action type for this user: '{etype}'")

    final_score = float(min(100.0, max(0.0, round(score, 1))))
    return final_score, reasons


def sync_employee_risk_profile(
    db: Session,
    employee_id: str,
    tenant_id: str,
    historical_events: List[Dict[str, Any]]
) -> RiskProfile:
    """
    Recalculate and persist the employee's baseline behavioral profile.
    """
    baseline = calculate_employee_baseline(historical_events)

    profile = db.query(RiskProfile).filter(
        RiskProfile.employee_id == employee_id,
        RiskProfile.tenant_id == tenant_id
    ).first()

    now = datetime.now(timezone.utc)
    if not profile:
        profile = RiskProfile(
            tenant_id=tenant_id,
            employee_id=employee_id,
            overall_score=0.0,
            behavior_baseline=baseline,
            anomaly_history=[],
            last_calculated=now
        )
        db.add(profile)
    else:
        profile.behavior_baseline = baseline
        profile.last_calculated = now

    db.commit()
    db.refresh(profile)
    return profile

