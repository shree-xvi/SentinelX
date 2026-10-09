from backend.app.models.integration import SiemIntegration
from backend.app.services.siem_service import (
    alert_to_cef,
    alert_to_json,
    forward_alert,
    render_message,
)


class _FakeAlert:
    id = "alert-xyz"
    alert_type = "DATA_EXFILTRATION"
    severity = "CRITICAL"
    risk_score = 95.0
    risk_level = "CRITICAL"
    source_ip = "45.33.32.156"
    status = "New"
    detected_at = None
    evidence = {"files": 25}


def _make_integration(db, tenant, **kwargs):
    tenant_id = tenant.id if tenant is not None else "tenant-test"
    integration = SiemIntegration(
        tenant_id=tenant_id,
        name=kwargs.get("name", "Splunk HEC"),
        provider=kwargs.get("provider", "splunk_hec"),
        endpoint=kwargs.get("endpoint", "https://splunk.example.com/services/collector"),
        format=kwargs.get("format", "json"),
        auth_token=kwargs.get("auth_token"),
        enabled=kwargs.get("enabled", True),
    )
    if db is None:
        # Pure render test — no persistence needed.
        return integration
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


def test_alert_to_json():
    payload = alert_to_json(_FakeAlert())
    assert payload["event"] == "sentinelx.alert"
    assert payload["alert"]["type"] == "DATA_EXFILTRATION"
    assert payload["alert"]["risk_score"] == 95.0


def test_alert_to_cef_format():
    cef = alert_to_cef(_FakeAlert())
    assert cef.startswith("CEF:0|SentinelX|ITD|1.0|DATA_EXFILTRATION")
    assert "src=45.33.32.156" in cef
    # CRITICAL maps to CEF severity 9.
    assert cef.split("|")[6] == "9"


def test_render_message_json():
    integration = _make_integration(None, None, format="json")  # not persisted
    headers, body = render_message(integration, _FakeAlert())
    assert headers["Content-Type"] == "application/json"
    assert "sentinelx.alert" in body


def test_render_message_cef():
    integration = _make_integration(None, None, format="cef")  # not persisted
    headers, body = render_message(integration, _FakeAlert())
    assert headers["Content-Type"] == "text/plain"
    assert body.startswith("CEF:0")


def test_render_message_includes_auth_token():
    integration = _make_integration(None, None, auth_token="hec-token")  # not persisted
    headers, body = render_message(integration, _FakeAlert())
    assert headers["Authorization"] == "Bearer hec-token"


def test_forward_alert_success(db_session, test_tenant):
    integration = _make_integration(db_session, test_tenant)

    def transport(url, headers, body):
        return 200, "ok"

    ok = forward_alert(db_session, integration, _FakeAlert(), transport=transport)
    assert ok is True
    assert integration.last_status == "ok"


def test_forward_alert_failure(db_session, test_tenant):
    integration = _make_integration(db_session, test_tenant)

    def transport(url, headers, body):
        return 503, "unavailable"

    ok = forward_alert(db_session, integration, _FakeAlert(), transport=transport)
    assert ok is False
    assert integration.last_status == "error"
    assert "503" in integration.last_error
