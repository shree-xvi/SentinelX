"""Forward security telemetry to an external SIEM.

Supports two wire formats:
  * ``json`` — a structured JSON document.
  * ``cef``  — ArcSight Common Event Format over HTTP.

The HTTP call is isolated behind an injectable transport for testability.
"""
import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from sqlalchemy.orm import Session

from backend.app.models.integration import SiemIntegration

Transport = Callable[[str, Dict[str, str], str], "tuple[int, str]"]

SEVERITY_TO_CEF = {"LOW": 3, "MEDIUM": 5, "HIGH": 7, "CRITICAL": 9}


def alert_to_json(alert: Any) -> Dict[str, Any]:
    detected = getattr(alert, "detected_at", None)
    return {
        "event": "sentinelx.alert",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "id": getattr(alert, "id", None),
            "type": getattr(alert, "alert_type", None),
            "severity": getattr(alert, "severity", None),
            "risk_score": getattr(alert, "risk_score", None),
            "risk_level": getattr(alert, "risk_level", None),
            "source_ip": getattr(alert, "source_ip", None),
            "status": getattr(alert, "status", None),
            "detected_at": detected.isoformat() if detected else None,
            "evidence": getattr(alert, "evidence", {}),
        },
    }


def alert_to_cef(alert: Any, vendor: str = "SentinelX", product: str = "ITD") -> str:
    """Render an alert as a CEF header line."""
    severity = getattr(alert, "severity", "MEDIUM")
    cef_severity = SEVERITY_TO_CEF.get(severity, 5)
    signature = getattr(alert, "alert_type", "ALERT")
    name = f"{signature} detected"
    # CEF extension fields (key=value, space-separated, values escaped).
    src = getattr(alert, "source_ip", None) or "unknown"
    detected = getattr(alert, "detected_at", None)
    detected_ms = int(detected.timestamp() * 1000) if detected else 0
    extension = (
        f"src={src} rt={detected_ms} "
        f"cs1Label=RiskScore cs1={getattr(alert, 'risk_score', 0)} "
        f"cs2Label=RiskLevel cs2={getattr(alert, 'risk_level', '')} "
        f"cs3Label=AlertID cs3={getattr(alert, 'id', '')}"
    )
    # Escape pipes in the header fields.
    header = f"CEF:0|{vendor}|{product}|1.0|{signature}|{name}|{cef_severity}"
    return f"{header}|{extension}"


def render_message(integration: SiemIntegration, alert: Any) -> "tuple[Dict[str, str], str]":
    if integration.format.lower() == "cef":
        headers = {"Content-Type": "text/plain"}
        body = alert_to_cef(alert)
    else:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(alert_to_json(alert))

    if integration.auth_token:
        headers["Authorization"] = f"Bearer {integration.auth_token}"
    return headers, body


def forward_alert(
    db: Session,
    integration: SiemIntegration,
    alert: Any,
    transport: Optional[Transport] = None,
) -> bool:
    """Forward a single alert to a SIEM integration. Returns success bool."""
    headers, body = render_message(integration, alert)
    try:
        if transport is None:
            status_code, text = _http_transport(integration.endpoint, headers, body)
        else:
            status_code, text = transport(integration.endpoint, headers, body)

        integration.last_sent_at = datetime.now(timezone.utc)
        if 200 <= status_code < 300:
            integration.last_status = "ok"
            integration.last_error = None
            ok = True
        else:
            integration.last_status = "error"
            integration.last_error = f"HTTP {status_code}: {text[:500]}"
            ok = False
    except Exception as exc:  # noqa: BLE001
        integration.last_status = "error"
        integration.last_error = str(exc)[:1000]
        ok = False

    db.commit()
    return ok


def _http_transport(url: str, headers: Dict[str, str], body: str) -> "tuple[int, str]":
    import httpx

    with httpx.Client(timeout=5.0) as client:
        resp = client.post(url, headers=headers, content=body)
        return resp.status_code, resp.text
