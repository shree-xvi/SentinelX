from backend.app.models.notification import NotificationChannel
from backend.app.services.notification_service import (
    build_alert_payload,
    dispatch_to_channel,
    notify_for_alert,
    severity_meets,
)


class _FakeAlert:
    id = "alert-1"
    alert_type = "BRUTE_FORCE"
    severity = "HIGH"
    risk_score = 85.0
    risk_level = "HIGH"
    source_ip = "198.51.100.1"
    status = "New"
    detected_at = None
    evidence = {"attempts": 5}


def _make_channel(db, tenant, **kwargs):
    channel = NotificationChannel(
        tenant_id=tenant.id,
        name=kwargs.get("name", "Ops Webhook"),
        channel_type="webhook",
        target=kwargs.get("target", "https://hooks.example.com/alert"),
        min_severity=kwargs.get("min_severity", "HIGH"),
        enabled=kwargs.get("enabled", True),
        secret=kwargs.get("secret"),
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return channel


def test_severity_meets_threshold():
    assert severity_meets("CRITICAL", "HIGH")
    assert severity_meets("HIGH", "HIGH")
    assert not severity_meets("MEDIUM", "HIGH")
    assert not severity_meets("LOW", "CRITICAL")


def test_build_alert_payload():
    payload = build_alert_payload(_FakeAlert())
    assert payload["event"] == "alert.created"
    assert payload["alert"]["type"] == "BRUTE_FORCE"
    assert payload["alert"]["source_ip"] == "198.51.100.1"
    assert "sent_at" in payload


def test_dispatch_success_records_sent(db_session, test_tenant):
    channel = _make_channel(db_session, test_tenant)

    def transport(url, headers, payload):
        assert url == channel.target
        return 200, "ok"

    log = dispatch_to_channel(db_session, channel, {"event": "test"}, transport=transport)
    assert log.status == "sent"
    assert log.response_status == 200


def test_dispatch_failure_records_error(db_session, test_tenant):
    channel = _make_channel(db_session, test_tenant)

    def transport(url, headers, payload):
        return 500, "server error"

    log = dispatch_to_channel(db_session, channel, {"event": "test"}, transport=transport)
    assert log.status == "failed"
    assert log.response_status == 500
    assert "500" in log.error


def test_dispatch_exception_is_captured(db_session, test_tenant):
    channel = _make_channel(db_session, test_tenant)

    def transport(url, headers, payload):
        raise ConnectionError("network down")

    log = dispatch_to_channel(db_session, channel, {"event": "test"}, transport=transport)
    assert log.status == "failed"
    assert "network down" in log.error


def test_signature_header_added_when_secret_set(db_session, test_tenant):
    channel = _make_channel(db_session, test_tenant, secret="topsecret")
    captured = {}

    def transport(url, headers, payload):
        captured.update(headers)
        return 200, "ok"

    dispatch_to_channel(db_session, channel, {"event": "test"}, transport=transport)
    assert "X-SentinelX-Signature" in captured
    assert len(captured["X-SentinelX-Signature"]) == 64  # sha256 hex


def test_notify_for_alert_respects_severity_gate(db_session, test_tenant):
    # Channel requires CRITICAL; a HIGH alert should be skipped.
    _make_channel(db_session, test_tenant, min_severity="CRITICAL")
    logs = notify_for_alert(
        db_session, test_tenant.id, _FakeAlert(), transport=lambda u, h, p: (200, "ok")
    )
    assert logs == []


def test_notify_for_alert_dispatches_when_threshold_met(db_session, test_tenant):
    _make_channel(db_session, test_tenant, min_severity="HIGH")
    logs = notify_for_alert(
        db_session, test_tenant.id, _FakeAlert(), transport=lambda u, h, p: (200, "ok")
    )
    assert len(logs) == 1
    assert logs[0].status == "sent"


def test_notify_for_alert_skips_disabled_channels(db_session, test_tenant):
    _make_channel(db_session, test_tenant, enabled=False, min_severity="LOW")
    logs = notify_for_alert(
        db_session, test_tenant.id, _FakeAlert(), transport=lambda u, h, p: (200, "ok")
    )
    assert logs == []
