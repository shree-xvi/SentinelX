import hashlib
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"

ALERTS_FILE = PROJECT_ROOT / "Logs" / "alerts.json"
STATUS_FILE = DASHBOARD_DIR / "status.json"
INVESTIGATIONS_FILE = PROJECT_ROOT / "Logs" / "alert_investigations.json"

HOST = "127.0.0.1"
PORT = 8080

HEARTBEAT_TIMEOUT_SECONDS = 10

VALID_STATUSES = {"New", "Investigating", "Resolved"}

MAX_NOTES_LENGTH = 5000
MAX_REQUEST_BYTES = 10000


def load_json_file(path, default):
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return default


def load_alerts():
    data = load_json_file(ALERTS_FILE, [])

    if not isinstance(data, list):
        return []

    return [
        item
        for item in data
        if isinstance(item, dict)
    ]


def load_investigations():
    data = load_json_file(INVESTIGATIONS_FILE, {})

    return data if isinstance(data, dict) else {}


def save_investigations(records):
    INVESTIGATIONS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_file = INVESTIGATIONS_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(
            records,
            file,
            indent=2,
            ensure_ascii=False,
        )

    temporary_file.replace(INVESTIGATIONS_FILE)


def alert_id(alert):
    canonical = json.dumps(
        alert,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def investigation_for(alert, records):
    record = records.get(
        alert_id(alert),
        {},
    )

    if not isinstance(record, dict):
        record = {}

    status = record.get(
        "status",
        "New",
    )

    if status not in VALID_STATUSES:
        status = "New"

    notes = record.get(
        "notes",
        "",
    )

    if not isinstance(notes, str):
        notes = ""

    updated_at = record.get(
        "updated_at"
    )

    history = record.get(
        "history",
        [],
    )

    if not isinstance(history, list):
        history = []

    clean_history = []

    for event in history:
        if not isinstance(event, dict):
            continue

        clean_history.append({
            "timestamp": event.get(
                "timestamp"
            ),
            "previous_status": event.get(
                "previous_status"
            ),
            "status": event.get(
                "status"
            ),
            "notes": event.get(
                "notes",
                "",
            ),
            "action": event.get(
                "action",
                "Investigation updated",
            ),
        })

    return {
        "status": status,
        "notes": notes,
        "updated_at": updated_at,
        "history": clean_history,
    }


def get_alert_payload():
    records = load_investigations()

    return [
        {
            "id": alert_id(alert),
            "data": alert,
            "investigation": investigation_for(
                alert,
                records,
            ),
        }
        for alert in load_alerts()
    ]


def get_monitor_status():
    stopped = {
        "status": "STOPPED",
        "message": (
            "Monitoring is stopped or "
            "no status is available."
        ),
        "updated_at": None,
    }

    data = load_json_file(
        STATUS_FILE,
        None,
    )

    if not isinstance(data, dict):
        return stopped

    if data.get("status") != "RUNNING":
        return {
            "status": "STOPPED",
            "message": data.get(
                "message",
                "Live monitoring has stopped.",
            ),
            "updated_at": data.get(
                "updated_at"
            ),
        }

    updated_at = data.get(
        "updated_at"
    )

    if not isinstance(updated_at, str):
        return stopped

    try:
        heartbeat = datetime.fromisoformat(
            updated_at
        )

        now = (
            datetime.now(heartbeat.tzinfo)
            if heartbeat.tzinfo
            else datetime.now()
        )

        age = (
            now - heartbeat
        ).total_seconds()

    except (ValueError, TypeError):
        return stopped

    if age < -5 or age > HEARTBEAT_TIMEOUT_SECONDS:
        return {
            "status": "STOPPED",
            "message": "Monitoring heartbeat expired.",
            "updated_at": updated_at,
        }

    return data


def send_json(
    handler,
    payload,
    status=200,
):
    body = json.dumps(
        payload,
        ensure_ascii=False,
    ).encode("utf-8")

    handler.send_response(status)

    handler.send_header(
        "Content-Type",
        "application/json; charset=utf-8",
    )

    handler.send_header(
        "Content-Length",
        str(len(body)),
    )

    handler.send_header(
        "Cache-Control",
        "no-store",
    )

    handler.send_header(
        "X-Content-Type-Options",
        "nosniff",
    )

    handler.end_headers()

    handler.wfile.write(body)


def send_file(
    handler,
    path,
    content_type,
):
    try:
        body = path.read_bytes()

    except OSError:
        send_json(
            handler,
            {
                "error": (
                    "Requested file "
                    "was not found"
                )
            },
            404,
        )

        return

    handler.send_response(200)

    handler.send_header(
        "Content-Type",
        content_type,
    )

    handler.send_header(
        "Content-Length",
        str(len(body)),
    )

    handler.send_header(
        "Cache-Control",
        "no-store",
    )

    handler.send_header(
        "X-Content-Type-Options",
        "nosniff",
    )

    handler.end_headers()

    handler.wfile.write(body)


class DashboardHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = urlparse(
            self.path
        ).path

        if path == "/":
            send_file(
                self,
                TEMPLATES_DIR / "index.html",
                "text/html; charset=utf-8",
            )
            return

        if path == "/static/style.css":
            send_file(
                self,
                STATIC_DIR / "style.css",
                "text/css; charset=utf-8",
            )
            return

        if path == "/static/dashboard.js":
            send_file(
                self,
                STATIC_DIR / "dashboard.js",
                "text/javascript; charset=utf-8",
            )
            return

        if path == "/api/alerts":
            send_json(
                self,
                {
                    "alerts": get_alert_payload()
                },
            )
            return

        if path == "/api/status":
            send_json(
                self,
                get_monitor_status(),
            )
            return

        send_json(
            self,
            {"error": "Not found"},
            404,
        )

    def do_POST(self):
        path = urlparse(
            self.path
        ).path

        if path != "/api/investigation":
            send_json(
                self,
                {"error": "Not found"},
                404,
            )
            return

        try:
            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )

        except ValueError:
            send_json(
                self,
                {"error": "Invalid content length"},
                400,
            )
            return

        if (
            length <= 0
            or length > MAX_REQUEST_BYTES
        ):
            send_json(
                self,
                {
                    "error": (
                        "Request body is empty "
                        "or too large"
                    )
                },
                413,
            )
            return

        try:
            raw_body = self.rfile.read(
                length
            )

            payload = json.loads(
                raw_body.decode("utf-8")
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            send_json(
                self,
                {
                    "error": (
                        "Request must contain "
                        "valid JSON"
                    )
                },
                400,
            )
            return

        if not isinstance(payload, dict):
            send_json(
                self,
                {
                    "error": (
                        "Request must be "
                        "a JSON object"
                    )
                },
                400,
            )
            return

        requested_id = payload.get("id")
        status = payload.get("status")
        notes = payload.get(
            "notes",
            "",
        )

        if (
            not isinstance(
                requested_id,
                str,
            )
            or not requested_id
        ):
            send_json(
                self,
                {
                    "error": (
                        "A valid alert "
                        "ID is required"
                    )
                },
                400,
            )
            return

        if (
            not isinstance(status, str)
            or status not in VALID_STATUSES
        ):
            send_json(
                self,
                {
                    "error": (
                        "Status must be "
                        "New, Investigating, "
                        "or Resolved"
                    )
                },
                400,
            )
            return

        if (
            not isinstance(notes, str)
            or len(notes) > MAX_NOTES_LENGTH
        ):
            send_json(
                self,
                {
                    "error": (
                        "Notes must be text "
                        "no longer than "
                        "5000 characters"
                    )
                },
                400,
            )
            return

        alerts = load_alerts()

        matching_alert = next(
            (
                alert
                for alert in alerts
                if alert_id(alert)
                == requested_id
            ),
            None,
        )

        if matching_alert is None:
            send_json(
                self,
                {
                    "error": (
                        "Alert not found. "
                        "Refresh the dashboard "
                        "and try again."
                    )
                },
                404,
            )
            return

        records = load_investigations()

        existing_record = records.get(
            requested_id,
            {},
        )

        if not isinstance(
            existing_record,
            dict,
        ):
            existing_record = {}

        previous_status = existing_record.get(
            "status",
            "New",
        )

        if previous_status not in VALID_STATUSES:
            previous_status = "New"

        previous_notes = existing_record.get(
            "notes",
            "",
        )

        if not isinstance(
            previous_notes,
            str,
        ):
            previous_notes = ""

        history = existing_record.get(
            "history",
            [],
        )

        if not isinstance(
            history,
            list,
        ):
            history = []

        now = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        status_changed = (
            previous_status != status
        )

        notes_changed = (
            previous_notes != notes
        )

        if status_changed and notes_changed:
            action = "Status and notes updated"

        elif status_changed:
            action = "Status changed"

        elif notes_changed:
            action = "Notes updated"

        else:
            action = "Investigation updated"

        history_event = {
            "timestamp": now,
            "previous_status": previous_status,
            "status": status,
            "notes": notes,
            "action": action,
        }

        history.append(
            history_event
        )

        record = {
            "status": status,
            "notes": notes,
            "updated_at": now,
            "history": history,
        }

        records[requested_id] = record

        try:
            save_investigations(records)

        except OSError:
            send_json(
                self,
                {
                    "error": (
                        "Could not write "
                        "investigation "
                        "data to disk"
                    )
                },
                500,
            )
            return

        send_json(
            self,
            {
                "message": (
                    "Investigation saved"
                ),
                "investigation": record,
            },
        )

    def log_message(
        self,
        format_string,
        *args,
    ):
        print(
            "[Dashboard] "
            + format_string % args
        )


def main():
    server = ThreadingHTTPServer(
        (HOST, PORT),
        DashboardHandler,
    )

    print(
        "SentinelX dashboard running at "
        f"http://{HOST}:{PORT}"
    )

    print(
        "Press Ctrl+C to stop the dashboard."
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print(
            "\nStopping SentinelX dashboard..."
        )

    finally:
        server.server_close()


if __name__ == "__main__":
    main()