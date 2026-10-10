import csv
import io
import json
from datetime import datetime, timezone, timedelta

from backend.app.services.report_service import build_summary, summary_to_csv, summary_to_json


def _seed_alert(client, auth_headers, ip="203.0.113.55"):
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "auth_failure",
            "username": "report_user",
            "source_ip": ip,
            "timestamp": (now - timedelta(seconds=10 * (5 - i))).isoformat(),
        }
        for i in range(5)
    ]
    client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)


def test_build_summary_structure(db_session, test_tenant):
    summary = build_summary(db_session, test_tenant, days=30)
    assert summary["organization"]["domain"] == "acme.corp"
    assert summary["period_days"] == 30
    assert "totals" in summary
    assert "alerts_by_severity" in summary
    assert "alerts" in summary


def test_summary_to_json_is_valid(db_session, test_tenant):
    summary = build_summary(db_session, test_tenant)
    text = summary_to_json(summary)
    parsed = json.loads(text)
    assert parsed["organization"]["name"] == "Acme Security Corp"


def test_summary_to_csv_with_alerts(db_session, test_tenant):
    # Seed an alert via the ORM path is complex; use a direct alert insert.
    from backend.app.models.alert import Alert

    alert = Alert(
        tenant_id=test_tenant.id,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        risk_score=80.0,
        risk_level="HIGH",
        source_ip="203.0.113.55",
        fingerprint="fp-report-1",
        status="New",
        evidence={},
        detected_at=datetime.now(timezone.utc),
    )
    db_session.add(alert)
    db_session.commit()

    summary = build_summary(db_session, test_tenant)
    csv_text = summary_to_csv(summary)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) >= 1
    assert rows[0]["alert_type"] == "BRUTE_FORCE"


def test_summary_to_csv_empty(db_session, test_tenant):
    summary = build_summary(db_session, test_tenant)
    csv_text = summary_to_csv(summary)
    assert csv_text.startswith("id,alert_type,severity")


def test_report_summary_endpoint_json(client, auth_headers):
    _seed_alert(client, auth_headers)
    res = client.get("/api/v1/reports/summary?format=json&days=30", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["totals"]["alerts"] >= 1


def test_report_summary_endpoint_csv(client, auth_headers):
    _seed_alert(client, auth_headers)
    res = client.get("/api/v1/reports/summary?format=csv", headers=auth_headers)
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "Content-Disposition" in res.headers
    rows = list(csv.DictReader(io.StringIO(res.text)))
    assert len(rows) >= 1


def test_report_rejects_invalid_format(client, auth_headers):
    res = client.get("/api/v1/reports/summary?format=xml", headers=auth_headers)
    assert res.status_code == 422


def test_report_requires_auth(client):
    assert client.get("/api/v1/reports/summary").status_code == 401
