import json
import logging

from backend.app.utils.logging import JsonFormatter, configure_logging, get_logger


def _make_record(**extra):
    record = logging.LogRecord(
        name="sentinelx.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_emits_valid_json():
    formatter = JsonFormatter()
    line = formatter.format(_make_record())
    payload = json.loads(line)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "sentinelx.test"
    assert payload["message"] == "hello world"
    assert "timestamp" in payload


def test_json_formatter_includes_structured_context():
    formatter = JsonFormatter()
    line = formatter.format(_make_record(tenant_id="t-1", alert_type="BRUTE_FORCE"))
    payload = json.loads(line)
    assert payload["tenant_id"] == "t-1"
    assert payload["alert_type"] == "BRUTE_FORCE"


def test_json_formatter_serializes_unserializable_values():
    class Weird:
        def __str__(self):
            return "weird"

    formatter = JsonFormatter()
    line = formatter.format(_make_record(thing=Weird()))
    payload = json.loads(line)  # must not raise
    assert payload["thing"] == "weird"


def test_configure_logging_is_idempotent():
    logger = configure_logging()
    handler_count = len(logger.handlers)
    configure_logging()
    assert len(logger.handlers) == handler_count


def test_get_logger_returns_child():
    logger = get_logger("api.events")
    assert logger.name == "sentinelx.api.events"


def test_security_headers_present(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["referrer-policy"] == "no-referrer"


def test_health_endpoint_exempt_from_rate_limit(client):
    # Health checks should never be rate limited even under heavy load.
    for _ in range(20):
        assert client.get("/health").status_code == 200
