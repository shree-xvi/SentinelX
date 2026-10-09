from unittest.mock import patch


def _create_integration(client, auth_headers, **overrides):
    payload = {
        "name": "Splunk HEC",
        "provider": "splunk_hec",
        "endpoint": "https://splunk.example.com/services/collector",
        "format": "json",
        "forward_scope": "alerts",
        "min_severity": "MEDIUM",
    }
    payload.update(overrides)
    return client.post("/api/v1/siem/integrations", json=payload, headers=auth_headers)


def test_create_and_list_integrations(client, auth_headers):
    res = _create_integration(client, auth_headers)
    assert res.status_code == 201
    integration = res.json()
    assert integration["name"] == "Splunk HEC"
    assert integration["format"] == "json"
    assert "auth_token" not in integration  # token must not be echoed

    list_res = client.get("/api/v1/siem/integrations", headers=auth_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) == 1


def test_update_integration(client, auth_headers):
    integration_id = _create_integration(client, auth_headers).json()["id"]
    res = client.patch(
        f"/api/v1/siem/integrations/{integration_id}",
        json={"enabled": False, "format": "cef"},
        headers=auth_headers,
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is False
    assert res.json()["format"] == "cef"


def test_delete_integration(client, auth_headers):
    integration_id = _create_integration(client, auth_headers).json()["id"]
    res = client.delete(f"/api/v1/siem/integrations/{integration_id}", headers=auth_headers)
    assert res.status_code == 204
    list_res = client.get("/api/v1/siem/integrations", headers=auth_headers)
    assert len(list_res.json()) == 0


def test_test_integration_dispatch(client, auth_headers):
    integration_id = _create_integration(client, auth_headers).json()["id"]
    with patch("backend.app.services.siem_service._http_transport") as mock:
        mock.return_value = (200, "ok")
        res = client.post(
            f"/api/v1/siem/integrations/{integration_id}/test", headers=auth_headers
        )
    assert res.status_code == 200
    assert res.json()["ok"] is True


def test_test_integration_reports_failure(client, auth_headers):
    integration_id = _create_integration(client, auth_headers).json()["id"]
    with patch("backend.app.services.siem_service._http_transport") as mock:
        mock.return_value = (500, "boom")
        res = client.post(
            f"/api/v1/siem/integrations/{integration_id}/test", headers=auth_headers
        )
    assert res.status_code == 200
    assert res.json()["ok"] is False
    assert res.json()["error"] is not None


def test_integrations_require_auth(client):
    assert client.get("/api/v1/siem/integrations").status_code == 401
