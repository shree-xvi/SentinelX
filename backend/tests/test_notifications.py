from unittest.mock import patch

from backend.app.models.notification import NotificationChannel


def _create_channel(client, auth_headers, **overrides):
    payload = {
        "name": "Ops Webhook",
        "channel_type": "webhook",
        "target": "https://hooks.example.com/alert",
        "min_severity": "HIGH",
    }
    payload.update(overrides)
    return client.post("/api/v1/notifications/channels", json=payload, headers=auth_headers)


def test_create_and_list_channels(client, auth_headers):
    res = _create_channel(client, auth_headers)
    assert res.status_code == 201
    channel = res.json()
    assert channel["name"] == "Ops Webhook"
    assert "secret" not in channel  # secret must never be echoed

    list_res = client.get("/api/v1/notifications/channels", headers=auth_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) == 1


def test_update_channel(client, auth_headers):
    channel_id = _create_channel(client, auth_headers).json()["id"]
    res = client.patch(
        f"/api/v1/notifications/channels/{channel_id}",
        json={"enabled": False, "min_severity": "CRITICAL"},
        headers=auth_headers,
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is False
    assert res.json()["min_severity"] == "CRITICAL"


def test_delete_channel(client, auth_headers):
    channel_id = _create_channel(client, auth_headers).json()["id"]
    res = client.delete(f"/api/v1/notifications/channels/{channel_id}", headers=auth_headers)
    assert res.status_code == 204
    list_res = client.get("/api/v1/notifications/channels", headers=auth_headers)
    assert len(list_res.json()) == 0


def test_test_channel_dispatch(client, auth_headers):
    channel_id = _create_channel(client, auth_headers).json()["id"]

    with patch("backend.app.services.notification_service._http_transport") as mock:
        mock.return_value = (200, "ok")
        res = client.post(
            f"/api/v1/notifications/channels/{channel_id}/test",
            json={"message": "hello"},
            headers=auth_headers,
        )
    assert res.status_code == 200
    assert res.json()["status"] == "sent"


def test_notification_logs_recorded(client, auth_headers):
    channel_id = _create_channel(client, auth_headers).json()["id"]
    with patch("backend.app.services.notification_service._http_transport") as mock:
        mock.return_value = (200, "ok")
        client.post(
            f"/api/v1/notifications/channels/{channel_id}/test",
            json={"message": "hello"},
            headers=auth_headers,
        )
    logs = client.get("/api/v1/notifications/logs", headers=auth_headers).json()
    assert len(logs) == 1
    assert logs[0]["status"] == "sent"


def test_channels_require_auth(client):
    assert client.get("/api/v1/notifications/channels").status_code == 401


def test_channel_create_requires_admin(client, db_session, test_tenant):
    from backend.app.models.user import User
    from backend.app.utils.security import hash_password, create_access_token

    analyst = User(
        tenant_id=test_tenant.id,
        email="analyst2@acme.corp",
        hashed_password=hash_password("Analyst123!"),
        role="analyst",
        is_active=True,
    )
    db_session.add(analyst)
    db_session.commit()
    token = create_access_token({"sub": analyst.id, "tenant_id": test_tenant.id, "role": analyst.role})
    headers = {"Authorization": f"Bearer {token}"}

    res = _create_channel(client, headers)
    assert res.status_code == 403


def test_alerts_trigger_notification(client, auth_headers, db_session):
    # Configure a channel that fires on HIGH, then ingest a brute-force alert.
    _create_channel(client, auth_headers, min_severity="HIGH")

    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "auth_failure",
            "username": "notif_target",
            "source_ip": "203.0.113.77",
            "timestamp": (now - timedelta(seconds=10 * (5 - i))).isoformat(),
        }
        for i in range(5)
    ]

    with patch("backend.app.services.notification_service._http_transport") as mock:
        mock.return_value = (200, "ok")
        client.post("/api/v1/events/batch", json={"events": events}, headers=auth_headers)

    logs = client.get("/api/v1/notifications/logs", headers=auth_headers).json()
    assert len(logs) >= 1
    assert logs[0]["status"] == "sent"
