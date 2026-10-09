from datetime import datetime, timezone, timedelta
from backend.app.detection.ueba import calculate_employee_baseline, detect_behavioral_anomaly


def test_calculate_employee_baseline():
    events = [
        {"timestamp": datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc), "source_ip": "192.168.1.10", "event_type": "auth_success"},
        {"timestamp": datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc), "source_ip": "192.168.1.10", "event_type": "file_read"},
        {"timestamp": datetime(2026, 10, 2, 9, 45, tzinfo=timezone.utc), "source_ip": "192.168.1.10", "event_type": "auth_success"},
        {"timestamp": datetime(2026, 10, 2, 11, 0, tzinfo=timezone.utc), "source_ip": "192.168.1.10", "event_type": "file_read"},
        {"timestamp": datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc), "source_ip": "192.168.1.10", "event_type": "auth_success"},
    ]

    baseline = calculate_employee_baseline(events)
    assert baseline["total_events"] == 5
    assert baseline["known_ips"] == ["192.168.1.10"]
    assert baseline["hourly_distribution"][9] == 3
    assert baseline["hourly_distribution"][10] == 1
    assert baseline["hourly_distribution"][11] == 1
    assert baseline["hourly_distribution"][3] == 0  # 3 AM was 0


def test_detect_behavioral_anomaly_rare_hour_and_ip():
    # Historical events during 9-11 AM from 192.168.1.10
    events = [
        {"timestamp": datetime(2026, 10, i, 10, 0, tzinfo=timezone.utc), "source_ip": "192.168.1.10", "event_type": "file_read"}
        for i in range(1, 10)
    ]
    baseline = calculate_employee_baseline(events)

    # Anomaly event at 3 AM from an unfamiliar IP address
    anomaly_event = {
        "timestamp": datetime(2026, 10, 15, 3, 30, tzinfo=timezone.utc),
        "source_ip": "185.220.101.5",
        "event_type": "file_export"
    }

    score, reasons = detect_behavioral_anomaly(anomaly_event, baseline)
    assert score >= 50.0
    assert any("03:00 never observed" in r for r in reasons)
    assert any("unrecognised source IP" in r for r in reasons)


def test_employee_baseline_api_endpoint(client, auth_headers):
    # Create employee
    emp_res = client.post("/api/v1/employees", json={"employee_id": "EMP-UEBA-1", "name": "Evelyn Reed"}, headers=auth_headers)
    emp_id = emp_res.json()["id"]

    # Send historical events for this employee
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "auth_success",
            "username": "Evelyn Reed",
            "employee_id": "EMP-UEBA-1",
            "source_ip": "10.0.0.100",
            "timestamp": (now - timedelta(hours=i)).isoformat()
        }
        for i in range(6)
    ]
    client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)

    # Query baseline endpoint
    baseline_res = client.get(f"/api/v1/employees/{emp_id}/baseline", headers=auth_headers)
    assert baseline_res.status_code == 200
    data = baseline_res.json()
    assert data["employee_id"] == "EMP-UEBA-1"
    assert "baseline" in data
    assert "hourly_distribution" in data["baseline"]

