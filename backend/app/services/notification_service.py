"""Outbound notification dispatch for security alerts.

The actual HTTP call is isolated behind a small injectable transport so the
service can be unit-tested without network access.
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.app.models.notification import NotificationChannel, NotificationLog

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Transport signature: (url, headers, payload_dict) -> (status_code, body_text)
Transport = Callable[[str, Dict[str, str], Dict[str, Any]], "tuple[int, str]"]


def build_alert_payload(alert: Any) -> Dict[str, Any]:
    """Build a provider-agnostic JSON payload describing an alert."""
    return {
        "event": "alert.created",
        "alert": {
            "id": getattr(alert, "id", None),
            "type": getattr(alert, "alert_type", None),
            "severity": getattr(alert, "severity", None),
            "risk_score": getattr(alert, "risk_score", None),
            "risk_level": getattr(alert, "risk_level", None),
            "source_ip": getattr(alert, "source_ip", None),
            "status": getattr(alert, "status", None),
            "detected_at": (
                alert.detected_at.isoformat()
                if getattr(alert, "detected_at", None)
                else None
            ),
            "evidence": getattr(alert, "evidence", {}),
        },
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def severity_meets(alert_severity: str, min_severity: str) -> bool:
    return SEVERITY_RANK.get(alert_severity, 0) >= SEVERITY_RANK.get(min_severity, 0)


def dispatch_to_channel(
    db: Session,
    channel: NotificationChannel,
    payload: Dict[str, Any],
    alert_id: Optional[str] = None,
    transport: Optional[Transport] = None,
) -> NotificationLog:
    """Send a payload to a single channel and record the outcome.

    Never raises: delivery failures are captured in the returned log so a
    misbehaving receiver cannot break alert ingestion.
    """
    log = NotificationLog(
        tenant_id=channel.tenant_id,
        channel_id=channel.id,
        alert_id=alert_id,
        status="pending",
        payload=payload,
    )
    db.add(log)

    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if channel.secret:
        headers["X-SentinelX-Signature"] = _sign(channel.secret, body)

    try:
        if transport is None:
            status_code, text = _http_transport(channel.target, headers, payload)
        else:
            status_code, text = transport(channel.target, headers, payload)

        log.response_status = status_code
        if 200 <= status_code < 300:
            log.status = "sent"
        else:
            log.status = "failed"
            log.error = f"Receiver returned {status_code}: {text[:500]}"
    except Exception as exc:  # noqa: BLE001 - delivery must never propagate
        log.status = "failed"
        log.error = str(exc)[:1000]

    db.commit()
    db.refresh(log)
    return log


def notify_for_alert(
    db: Session,
    tenant_id: str,
    alert: Any,
    transport: Optional[Transport] = None,
) -> List[NotificationLog]:
    """Fan out an alert to every enabled channel meeting its severity gate."""
    channels = (
        db.query(NotificationChannel)
        .filter(
            NotificationChannel.tenant_id == tenant_id,
            NotificationChannel.enabled.is_(True),
        )
        .all()
    )
    payload = build_alert_payload(alert)
    logs: List[NotificationLog] = []
    for channel in channels:
        if not severity_meets(getattr(alert, "severity", "LOW"), channel.min_severity):
            continue
        logs.append(
            dispatch_to_channel(db, channel, payload, alert_id=getattr(alert, "id", None), transport=transport)
        )
    return logs


def _http_transport(url: str, headers: Dict[str, str], payload: Dict[str, Any]) -> "tuple[int, str]":
    """Default transport using httpx (already a project dependency)."""
    import httpx

    with httpx.Client(timeout=5.0) as client:
        resp = client.post(url, headers=headers, json=payload)
        return resp.status_code, resp.text
