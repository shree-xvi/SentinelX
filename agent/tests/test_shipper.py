import time
import httpx
from agent.shipper import EventShipper


class MockTransport(httpx.BaseTransport):
    def __init__(self, status_code: int = 201, response_json: list = None):
        self.status_code = status_code
        self.response_json = response_json or []
        self.call_count = 0
        self.last_payload = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.call_count += 1
        import json
        self.last_payload = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            status_code=self.status_code,
            json=self.response_json,
            headers={"Content-Type": "application/json"}
        )


def test_shipper_enqueue_and_batch_flush():
    mock_transport = MockTransport(status_code=201, response_json=[{"id": "alert-1"}])
    client = httpx.Client(transport=mock_transport)

    shipper = EventShipper(
        server_url="http://mock-server:8000",
        api_key="snx_live_test_api_key",
        batch_size=5,
        flush_interval_seconds=10.0,
        client=client
    )

    # Enqueue 4 events - should not trigger batch flush yet
    for i in range(4):
        assert shipper.enqueue({"event_type": "auth_success", "username": f"user_{i}"})
    assert not shipper.should_flush()

    # 5th event reaches batch_size=5
    shipper.enqueue({"event_type": "auth_success", "username": "user_4"})
    assert shipper.should_flush()

    # Flush batch
    alerts = shipper.flush()
    assert len(alerts) == 1
    assert mock_transport.call_count == 1
    assert len(mock_transport.last_payload["events"]) == 5
    assert shipper.queue_size == 0


def test_shipper_interval_flush():
    mock_transport = MockTransport(status_code=201)
    client = httpx.Client(transport=mock_transport)

    shipper = EventShipper(
        server_url="http://mock-server:8000",
        api_key="snx_live_test_api_key",
        batch_size=50,
        flush_interval_seconds=0.05,  # 50ms
        client=client
    )

    shipper.enqueue({"event_type": "file_access", "username": "alice"})
    time.sleep(0.08)

    assert shipper.should_flush()
    shipper.flush()
    assert mock_transport.call_count == 1


def test_shipper_requeue_on_network_failure():
    mock_transport = MockTransport(status_code=500)
    client = httpx.Client(transport=mock_transport)

    shipper = EventShipper(
        server_url="http://mock-server:8000",
        api_key="snx_live_test_api_key",
        batch_size=2,
        client=client
    )

    shipper.enqueue({"event_type": "auth_failure", "username": "bob"})
    shipper.enqueue({"event_type": "auth_failure", "username": "bob"})

    alerts = shipper.flush()
    assert len(alerts) == 0
    # Events were re-enqueued on 500 error
    assert shipper.queue_size == 2

