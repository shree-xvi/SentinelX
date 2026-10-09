import tempfile
from pathlib import Path
from datetime import datetime, timezone
import httpx
from fastapi.testclient import TestClient

from backend.app.main import app
from agent.agent import SentinelXAgent
from agent.shipper import EventShipper
from agent.collectors.auth_collector import AuthCollector


def test_agent_to_backend_e2e_integration(client, auth_headers):
    # 1. Generate an API Key from the backend
    key_res = client.post("/api/v1/auth/api-keys", json={"name": "E2E-Agent-Host"}, headers=auth_headers)
    assert key_res.status_code == 201
    raw_api_key = key_res.json()["raw_key"]

    # 2. Create custom HTTP transport that forwards directly to the FastAPI TestClient app
    # Starlette/FastAPI TestClient uses httpx internally
    transport = httpx.WSGITransport(app=app) if hasattr(httpx, "WSGITransport") else None
    # Alternatively use client as the transport mechanism or direct custom transport:
    class TestClientTransport(httpx.BaseTransport):
        def __init__(self, test_client: TestClient):
            self.test_client = test_client

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            import json
            headers = dict(request.headers)
            body = json.loads(request.content.decode("utf-8")) if request.content else None
            path = request.url.path
            resp = self.test_client.post(path, json=body, headers=headers)
            return httpx.Response(
                status_code=resp.status_code,
                json=resp.json(),
                headers={"Content-Type": "application/json"}
            )

    custom_client = httpx.Client(transport=TestClientTransport(client))

    # 3. Create a temporary auth log file for the AuthCollector
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        # Write 5 failed login lines from same IP to trigger brute force
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        for _ in range(5):
            f.write(f"{now_str} WARN Login failed user=target_victim ip=192.168.1.77\n")
        f.flush()
        temp_log = Path(f.name)

    try:
        # 4. Instantiate Agent with AuthCollector pointing to temp_log
        shipper = EventShipper(
            server_url="http://testserver",
            api_key=raw_api_key,
            batch_size=5,
            flush_interval_seconds=1.0,
            client=custom_client
        )

        agent_config = {
            "server": {"url": "http://testserver", "api_key": raw_api_key},
            "shipping": {"batch_size": 5, "flush_interval_seconds": 1.0},
            "collectors": {
                "auth": {"enabled": True, "log_path": str(temp_log)},
                "file": {"enabled": False},
                "usb": {"enabled": False},
                "process": {"enabled": False},
                "network": {"enabled": False},
            }
        }

        agent = SentinelXAgent(config=agent_config, shipper=shipper)

        # 5. Run one agent collection cycle
        collected_count = agent.run_cycle()
        assert collected_count == 5

        # 6. Verify alerts were generated and stored in backend
        alerts_res = client.get("/api/v1/alerts", headers=auth_headers)
        assert alerts_res.status_code == 200
        alerts = alerts_res.json()
        assert len(alerts) >= 1
        assert any(a["alert_type"] == "BRUTE_FORCE" and a["source_ip"] == "192.168.1.77" for a in alerts)

    finally:
        temp_log.unlink(missing_ok=True)

