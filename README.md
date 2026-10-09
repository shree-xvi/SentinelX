
# SentinelX 🔐

**A Python-based authentication security monitoring and detection system.**

SentinelX analyzes authentication logs, detects suspicious login activity, assigns risk scores to security alerts, and supports investigation through a local web dashboard.

## Features

### Detection Engine
- Parses authentication logs and extracts timestamps, usernames, source IP addresses, and login outcomes.
- Detects potential brute-force login attempts.
- Identifies suspicious login activity.
- Detects multi-account login patterns.
- Uses configurable detection thresholds and time windows.
- Assigns risk scores and severity levels to alerts.

### Alert Management
- Stores detected alerts in JSON format.
- Prevents duplicate alerts within the configured deduplication window.
- Generates alert summaries and reports.
- Supports IP-based alert investigation.

### Live Monitoring
- Monitors authentication logs for newly appended entries.
- Handles incomplete log lines until they are complete.
- Detects log truncation and file replacement.
- Maintains a configurable limit on recent events.
- Publishes monitoring status for the dashboard.

### Security Dashboard
- Provides a local web interface for reviewing alerts.
- Displays alert risk information and monitoring status.
- Supports investigation statuses: New, Investigating, and Resolved.
- Allows investigators to add notes.
- Maintains an investigation history and audit trail.

### Configuration
- Loads settings from `config/sentinelx.json`.
- Supports configurable brute-force thresholds and time windows.
- Configures monitoring intervals and event retention.
- Configures dashboard host, port, and heartbeat timeout.
- Validates configuration values and falls back to defaults when necessary.

### Testing
- Automated unit and integration tests.
- Configuration validation and fallback tests.
- Detection and monitoring integration tests.
- Dashboard configuration and heartbeat tests.

**Current test status: 110 tests passing.**

## Project Structure

```text
SentinelX/
├── Logs/
│   ├── auth.log
│   ├── alerts.json
│   └── alert_investigations.json
├── config/
│   └── sentinelx.json
├── src/
│   ├── collectors/
│   ├── config/
│   │   ├── config_loader.py
│   │   ├── test_config_loader.py
│   │   ├── test_config_integration.py
│   │   ├── test_monitor_integration.py
│   │   └── test_dashboard_integration.py
│   ├── dashboard/
│   │   ├── app.py
│   │   ├── status.json
│   │   ├── templates/
│   │   │   └── index.html
│   │   └── static/
│   │       ├── style.css
│   │       └── dashboard.js
│   ├── detection/
│   │   ├── brute_force.py
│   │   ├── suspicious_login.py
│   │   ├── multi_account.py
│   │   ├── engine.py
│   │   └── risk_score.py
│   ├── parsers/
│   │   └── auth_log_parser.py
│   ├── utils/
│   │   ├── alert_storage.py
│   │   └── alert_report.py
│   └── main.py
├── .gitignore
├── README.md
└── requirements.txt
```

*The tree highlights the main components; additional test files are present throughout `src/`.*

## Requirements

- Python 3.12 or a compatible Python version.
- Git.
- A modern web browser for the dashboard.

The dashboard uses Python's built-in HTTP server. No separate web framework is required for it.

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/shree-xvi/SentinelX.git
cd SentinelX
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run commands from the project root with the virtual environment activated.

### Run a one-time scan

```powershell
python src/main.py
```

Parses the configured authentication log, runs detection rules, and saves new alerts.

### Start live monitoring

```powershell
python src/main.py --watch
```

Monitors the authentication log for new events. Press `Ctrl+C` to stop monitoring.

### Generate an alert report

```powershell
python src/main.py --report
```

Displays a summary of saved alerts.

### Investigate an IP address

```powershell
python src/main.py --investigate 192.168.1.20
```

Replace the example IP address with the IPv4 address you want to investigate.

### Launch the dashboard

Open a **second PowerShell terminal** from the project root and activate the virtual environment if necessary.

```powershell
.\venv\Scripts\Activate.ps1
python src/dashboard/app.py
```

Open the dashboard in your browser:

http://127.0.0.1:8080

The default dashboard binds to the local machine. Keep the dashboard and monitoring process running in their respective terminals when using them together.

## Configuration

SentinelX reads its settings from `config/sentinelx.json`.

Example configuration:

```json
{
    "detection": {
        "brute_force": {
            "threshold": 5,
            "window_minutes": 5
        }
    },
    "risk": {
        "medium_threshold": 30,
        "high_threshold": 60,
        "critical_threshold": 80
    },
    "monitor": {
        "poll_seconds": 1,
        "max_watch_events": 1000
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8080,
        "heartbeat_timeout_seconds": 10
    }
}
```

| Setting | Default | Purpose |
|---|---:|---|
| `detection.brute_force.threshold` | `5` | Failed attempts required to trigger brute-force detection |
| `detection.brute_force.window_minutes` | `5` | Detection time window in minutes |
| `risk.medium_threshold` | `30` | Minimum score for MEDIUM risk |
| `risk.high_threshold` | `60` | Minimum score for HIGH risk |
| `risk.critical_threshold` | `80` | Minimum score for CRITICAL risk |
| `monitor.poll_seconds` | `1` | Watch-mode polling interval in seconds |
| `monitor.max_watch_events` | `1000` | Maximum recent events retained in memory |
| `dashboard.host` | `127.0.0.1` | Dashboard server bind address |
| `dashboard.port` | `8080` | Dashboard server port |
| `dashboard.heartbeat_timeout_seconds` | `10` | Time after which a stale monitoring heartbeat is considered expired |

The configuration loader validates supported values and uses defaults for missing or invalid settings. The dashboard host and port determine where the local dashboard server listens.

## Detection Logic

SentinelX currently includes brute-force detection, suspicious-login detection, and multi-account detection.

The brute-force rule flags a potential attack when the configured number of failed login attempts occurs within the configured time window. Its default is five failed attempts within five minutes.

Risk scores and severity levels help prioritize alerts. These signals support investigation; they do not independently establish that an account has been compromised.

## Alert Storage and Investigation

Generated data is stored locally:

- `Logs/alerts.json` — detected security alerts.
- `Logs/alert_investigations.json` — investigation statuses, notes, and history.
- `src/dashboard/status.json` — monitoring status consumed by the dashboard.

These files contain generated runtime data rather than source code. Ensure the relevant runtime files are excluded from version control as appropriate.

## Run Tests

Run the complete unit and integration test suite from the project root:

```powershell
python -m unittest discover -s src -p "test_*.py" -v
```

The latest recorded test result is **110 tests passing**. Run the command again after changes to verify the current state.

## Limitations

- SentinelX is an educational security-monitoring prototype, not a replacement for a production SIEM.
- Detection quality depends on the available log formats and detection rules.
- Sample authentication logs are used for demonstration.
- The dashboard is designed for local use and does not provide production-grade authentication or access control.
- Alerts should be reviewed and validated before taking security action.

## Disclaimer

SentinelX is an educational cybersecurity project. Use it only with systems and logs you are authorized to access. Detection results should be reviewed before taking security action.

## Future Improvements

- Support additional authentication log formats and data sources.
- Expand detection rules and improve detection accuracy.
- Add authenticated dashboard access and stronger deployment security.
- Add automated testing for end-to-end monitoring and dashboard workflows.
- Explore integration with external security monitoring systems.

## Author

**Shreenath Yadav**

GitHub: [@shree-xvi](https://github.com/shree-xvi)
