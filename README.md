
# SentinelX 🔐

A Python-based security monitoring prototype that analyzes authentication logs, detects potential brute-force login attacks, and stores security alerts.

## Features

- Parses authentication log entries.
- Extracts timestamps and source IP addresses.
- Detects brute-force patterns using a configurable threshold.
- Flags five or more failed login attempts within five minutes.
- Assigns severity levels to detected alerts.
- Stores alerts in a JSON file.
- Skips duplicate alerts.
- Includes unit tests for log parsing and brute-force detection.

## Project Structure

```text
SentinelX/
├── Logs/
│   └── auth.log
├── src/
│   ├── collectors/
│   ├── detection/
│   │   ├── brute_force.py
│   │   └── test_brute_force.py
│   ├── parsers/
│   │   ├── auth_log_parser.py
│   │   └── test_auth_log_parser.py
│   ├── utils/
│   │   └── alert_storage.py
│   └── main.py
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
```

## Requirements

- Python 3.12 or a compatible Python version
- Git

## Setup

Clone the repository:

```bash
git clone https://github.com/shree-xvi/SentinelX.git
cd SentinelX
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Run SentinelX from the project root:

```powershell
python src/main.py
```

## Run Tests

Run the test suite from the project root:

```powershell
python -m unittest discover -s src -p "test_*.py" -v
```

## Detection Logic

SentinelX currently flags a potential brute-force attack when an IP address has at least five failed login attempts within a five-minute window.

This is a demonstration rule, not proof that an attack has occurred. The project currently uses sample authentication logs.

## Alert Storage

Detected alerts are stored in `Logs/alerts.json`. This generated file is excluded from Git.

## Disclaimer

SentinelX is an educational cybersecurity project. Use it only with logs you are authorized to access. Detection results should be reviewed before taking security action.

## Future Improvements

- Add more detection rules.
- Improve log format support.
- Add structured logging and reporting.
- Build a web dashboard.
- Expand automated test coverage.

## Author

**Shreenath Yadav**

GitHub: [@shree-xvi](https://github.com/shree-xvi)
