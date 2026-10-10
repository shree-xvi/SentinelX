from datetime import datetime, timezone, timedelta


def test_after_hours_access_detection(client, auth_headers):
    # Event at 02:30 AM (outside 09:00 - 18:00)
    now = datetime(2026, 10, 14, 2, 30, 0, tzinfo=timezone.utc)  # Wednesday 2:30 AM
    events = [
        {
            "event_type": "auth_success",
            "username": "night_owl",
            "source_ip": "192.168.1.55",
            "timestamp": now.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "AFTER_HOURS_ACCESS" for a in alerts)


def test_impossible_travel_detection(client, auth_headers):
    # User logs in from New York, then 30 minutes later from London (3,400+ miles apart)
    t1 = datetime(2026, 10, 14, 10, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(minutes=30)

    events = [
        {
            "event_type": "auth_success",
            "username": "traveler",
            "source_ip": "198.51.100.1",
            "event_data": {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
            "timestamp": t1.isoformat()
        },
        {
            "event_type": "auth_success",
            "username": "traveler",
            "source_ip": "203.0.113.1",
            "event_data": {"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278},
            "timestamp": t2.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "IMPOSSIBLE_TRAVEL" for a in alerts)


def test_data_exfiltration_detection(client, auth_headers):
    # User downloads 25 sensitive files within 5 minutes (exceeds count_threshold=20)
    now = datetime(2026, 10, 14, 14, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "file_download",
            "username": "data_hoarder",
            "source_ip": "10.0.0.44",
            "event_data": {"filename": f"patent_draft_{i}.pdf", "bytes": 2 * 1024 * 1024},
            "timestamp": (now + timedelta(seconds=i * 5)).isoformat()
        }
        for i in range(25)
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "DATA_EXFILTRATION" for a in alerts)


def test_mass_file_operations_detection(client, auth_headers):
    # User deletes 35 files in bulk within 5 minutes
    now = datetime(2026, 10, 14, 15, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "file_delete",
            "username": "angry_admin",
            "source_ip": "10.0.0.12",
            "event_data": {"filepath": f"/var/data/shared/doc_{i}.docx"},
            "timestamp": (now + timedelta(seconds=i * 4)).isoformat()
        }
        for i in range(35)
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "MASS_FILE_OPERATIONS" for a in alerts)


def test_usb_device_usage_detection(client, auth_headers):
    now = datetime(2026, 10, 14, 16, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "usb_mount",
            "username": "sam_usb",
            "source_ip": "192.168.1.88",
            "event_data": {
                "device_id": "USB_SANDISK_ULTRA_64GB_9901",
                "device_name": "SanDisk Ultra 64GB",
                "volume_name": "E:\\"
            },
            "timestamp": now.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "USB_DEVICE_USAGE" for a in alerts)


def test_privilege_escalation_detection(client, auth_headers):
    now = datetime(2026, 10, 14, 11, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "sudo_exec",
            "username": "intern_dev",
            "source_ip": "10.0.0.99",
            "event_data": {"command": "sudo -i", "target_role": "root"},
            "timestamp": now.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "PRIVILEGE_ESCALATION" for a in alerts)


def test_abnormal_resource_access_detection(client, auth_headers):
    now = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "file_access",
            "username": "curious_george",
            "source_ip": "10.0.0.77",
            "event_data": {"filepath": "/finance/executive/payroll_salaries_2026.xlsx"},
            "timestamp": now.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "ABNORMAL_RESOURCE_ACCESS" for a in alerts)


def test_shadow_it_detection(client, auth_headers):
    now = datetime(2026, 10, 14, 13, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "http_request",
            "username": "uploader",
            "source_ip": "10.0.0.50",
            "event_data": {"domain": "https://wetransfer.com/upload", "bytes": 10485760},
            "timestamp": now.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "SHADOW_IT_USAGE" for a in alerts)


def test_email_anomaly_detection(client, auth_headers):
    now = datetime(2026, 10, 14, 17, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "email_send",
            "username": "sales_lead",
            "source_ip": "10.0.0.22",
            "event_data": {
                "recipients": ["competitor_contact@gmail.com"],
                "subject": "Fwd: Enterprise Customer List & Pricing",
                "attachment_size_bytes": 15 * 1024 * 1024
            },
            "timestamp": now.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "ANOMALOUS_EMAIL_ACTIVITY" for a in alerts)


def test_flight_risk_signals_detection(client, auth_headers):
    now = datetime(2026, 10, 14, 14, 30, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_type": "web_visit",
            "username": "disgruntled_engineer",
            "source_ip": "10.0.0.18",
            "event_data": {"url": "https://www.linkedin.com/jobs/search/?keywords=Staff+Engineer"},
            "timestamp": now.isoformat()
        }
    ]
    res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
    assert res.status_code == 201
    alerts = res.json()
    assert any(a["alert_type"] == "FLIGHT_RISK_SIGNALS" for a in alerts)


def test_policy_disable_rule(client, auth_headers):
    # Disable USB rule via policy
    policies_res = client.get("/api/v1/policies", headers=auth_headers)
    policies = policies_res.json()
    usb_policy = next((p for p in policies if p["rule_type"] == "USB_DEVICE_USAGE"), None)

    if usb_policy:
        client.patch(f"/api/v1/policies/{usb_policy['id']}", json={"enabled": False}, headers=auth_headers)

        # Trigger USB event
        events = [
            {
                "event_type": "usb_mount",
                "username": "permitted_user",
                "source_ip": "10.0.0.1",
                "event_data": {"device_id": "USB_TEST_DISABLE"},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
        res = client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)
        alerts = res.json()
        assert not any(a["alert_type"] == "USB_DEVICE_USAGE" for a in alerts)

