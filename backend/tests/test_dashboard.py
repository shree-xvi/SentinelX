from datetime import datetime, timezone, timedelta


def test_dashboard_overview_and_analytics(client, auth_headers):
    # Ingest event to produce an alert
    now = datetime.now(timezone.utc)
    events = [
        {"event_type": "auth_failure", "username": "bad_actor", "source_ip": "10.10.10.10", "timestamp": now.isoformat()}
        for _ in range(5)
    ]
    client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)

    # 1. Overview
    overview_res = client.get("/api/v1/dashboard/overview", headers=auth_headers)
    assert overview_res.status_code == 200
    data = overview_res.json()
    assert data["total_alerts"] >= 1
    assert "severities" in data
    assert "risk_levels" in data

    # 2. Rule stats
    rule_res = client.get("/api/v1/dashboard/rule-stats", headers=auth_headers)
    assert rule_res.status_code == 200
    rule_data = rule_res.json()
    assert "BRUTE_FORCE" in rule_data

    # 3. Top risks
    risks_res = client.get("/api/v1/dashboard/top-risks", headers=auth_headers)
    assert risks_res.status_code == 200
    assert isinstance(risks_res.json(), list)

    # 4. Timeline
    timeline_res = client.get("/api/v1/dashboard/timeline", headers=auth_headers)
    assert timeline_res.status_code == 200
    assert isinstance(timeline_res.json(), list)

