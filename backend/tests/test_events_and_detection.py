from datetime import datetime, timezone, timedelta


def test_ingest_single_event(client, auth_headers):
    payload = {
        "event_type": "auth_success",
        "username": "alice",
        "source_ip": "10.0.0.15",
        "source": "vpn_portal",
        "event_data": {"protocol": "OpenVPN"}
    }
    response = client.post("/api/v1/events", json=payload, headers=auth_headers)
    assert response.status_code == 201
    assert isinstance(response.json(), list)


def test_ingest_batch_events_with_api_key(client, auth_headers):
    # 1. Generate an API Key
    key_res = client.post("/api/v1/auth/api-keys", json={"name": "Test Collector"}, headers=auth_headers)
    raw_key = key_res.json()["raw_key"]

    # 2. Ingest batch events using X-API-Key header
    now = datetime.now(timezone.utc)
    batch = {
        "events": [
            {
                "event_type": "file_access",
                "username": "charlie",
                "source_ip": "192.168.1.100",
                "event_data": {"filepath": "/confidential/q3_forecast.xlsx"},
                "timestamp": (now - timedelta(minutes=2)).isoformat()
            },
            {
                "event_type": "file_access",
                "username": "charlie",
                "source_ip": "192.168.1.100",
                "event_data": {"filepath": "/confidential/merger_targets.docx"},
                "timestamp": now.isoformat()
            }
        ]
    }
    res = client.post("/api/v1/events/batch", json=batch, headers={"X-API-Key": raw_key})
    assert res.status_code == 201


def test_brute_force_detection_pipeline(client, auth_headers):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.42"

    # Send 5 failed login attempts within 2 minutes to trigger BRUTE_FORCE
    events = []
    for i in range(5):
        events.append({
            "event_type": "auth_failure",
            "username": "target_user",
            "source_ip": ip,
            "timestamp": (now - timedelta(seconds=10 * (5 - i))).isoformat()
        })

    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert len(alerts) >= 1

    alert = alerts[0]
    assert alert["alert_type"] == "BRUTE_FORCE"
    assert alert["source_ip"] == ip
    assert alert["severity"] in ("HIGH", "CRITICAL")
    assert alert["risk_score"] > 60

    # Verify alert appears in /alerts
    alerts_res = client.get("/api/v1/alerts", headers=auth_headers)
    assert alerts_res.status_code == 200
    all_alerts = alerts_res.json()
    assert any(a["alert_type"] == "BRUTE_FORCE" for a in all_alerts)


def test_suspicious_login_after_failures_detection(client, auth_headers):
    now = datetime.now(timezone.utc)
    ip = "203.0.113.88"

    # 3 failures followed by 1 success from same IP
    events = [
        {"event_type": "auth_failure", "username": "victim", "source_ip": ip, "timestamp": (now - timedelta(minutes=4)).isoformat()},
        {"event_type": "auth_failure", "username": "victim", "source_ip": ip, "timestamp": (now - timedelta(minutes=3)).isoformat()},
        {"event_type": "auth_failure", "username": "victim", "source_ip": ip, "timestamp": (now - timedelta(minutes=2)).isoformat()},
        {"event_type": "auth_success", "username": "victim", "source_ip": ip, "timestamp": (now - timedelta(minutes=1)).isoformat()},
    ]

    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "SUSPICIOUS_LOGIN_AFTER_FAILURES" for a in alerts)


def test_multi_account_spraying_detection(client, auth_headers):
    now = datetime.now(timezone.utc)
    ip = "192.0.2.111"

    # 3 failures across 3 different usernames from same IP
    events = [
        {"event_type": "auth_failure", "username": "user1", "source_ip": ip, "timestamp": (now - timedelta(minutes=3)).isoformat()},
        {"event_type": "auth_failure", "username": "user2", "source_ip": ip, "timestamp": (now - timedelta(minutes=2)).isoformat()},
        {"event_type": "auth_failure", "username": "user3", "source_ip": ip, "timestamp": (now - timedelta(minutes=1)).isoformat()},
    ]

    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "MULTI_ACCOUNT_FAILURES" for a in alerts)


def test_alert_deduplication(client, auth_headers):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.99"

    # Send 5 failures to trigger alert
    events = [
        {"event_type": "auth_failure", "username": "user_a", "source_ip": ip, "timestamp": now.isoformat()}
        for _ in range(5)
    ]

    # First batch triggers alert
    res1 = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert len(res1.json()) == 1

    # Immediate second batch with identical criteria should be deduplicated
    res2 = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert len(res2.json()) == 0  # Deduplicated and suppressed

