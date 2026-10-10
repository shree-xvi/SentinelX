from datetime import datetime, timezone, timedelta


def _seed_brute_force_alert(client, auth_headers, ip="203.0.113.10"):
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "auth_failure",
            "username": "brute_target",
            "source_ip": ip,
            "timestamp": (now - timedelta(seconds=10 * (5 - i))).isoformat(),
        }
        for i in range(5)
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    return res.json()


def test_list_alerts(client, auth_headers):
    _seed_brute_force_alert(client, auth_headers)
    res = client.get("/api/v1/alerts", headers=auth_headers)
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    assert alerts[0]["alert_type"] == "BRUTE_FORCE"


def test_get_alert_detail(client, auth_headers):
    _seed_brute_force_alert(client, auth_headers)
    alert_id = client.get("/api/v1/alerts", headers=auth_headers).json()[0]["id"]

    res = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers)
    assert res.status_code == 200
    alert = res.json()
    assert alert["id"] == alert_id
    assert "evidence" in alert
    assert "fingerprint" in alert


def test_get_missing_alert_returns_404(client, auth_headers):
    res = client.get("/api/v1/alerts/nope", headers=auth_headers)
    assert res.status_code == 404


def test_update_alert_status(client, auth_headers):
    _seed_brute_force_alert(client, auth_headers)
    alert_id = client.get("/api/v1/alerts", headers=auth_headers).json()[0]["id"]

    res = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "Investigating"},
        headers=auth_headers,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "Investigating"


def test_filter_alerts_by_severity(client, auth_headers):
    _seed_brute_force_alert(client, auth_headers)
    res = client.get("/api/v1/alerts?severity=HIGH", headers=auth_headers)
    assert res.status_code == 200
    for alert in res.json():
        assert alert["severity"] == "HIGH"


def test_filter_alerts_by_status(client, auth_headers):
    _seed_brute_force_alert(client, auth_headers)
    res = client.get("/api/v1/alerts?status=New", headers=auth_headers)
    assert res.status_code == 200
    for alert in res.json():
        assert alert["status"] == "New"


def test_update_alert_rejects_invalid_status(client, auth_headers):
    _seed_brute_force_alert(client, auth_headers)
    alert_id = client.get("/api/v1/alerts", headers=auth_headers).json()[0]["id"]

    res = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "NotAValidStatus"},
        headers=auth_headers,
    )
    assert res.status_code == 422


def test_query_events_audit_trail(client, auth_headers):
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "auth_success",
            "username": "audit_user",
            "source_ip": "10.0.0.5",
            "timestamp": now.isoformat(),
        }
    ]
    client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)

    res = client.get("/api/v1/events?username=audit_user", headers=auth_headers)
    assert res.status_code == 200
    records = res.json()
    assert len(records) >= 1
    assert records[0]["username"] == "audit_user"


def test_query_events_filter_by_type(client, auth_headers):
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "file_access",
            "username": "file_user",
            "source_ip": "10.0.0.6",
            "event_data": {"filepath": "/docs/report.pdf"},
            "timestamp": now.isoformat(),
        }
    ]
    client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)

    res = client.get("/api/v1/events?event_type=file_access", headers=auth_headers)
    assert res.status_code == 200
    for record in res.json():
        assert record["event_type"] == "file_access"
