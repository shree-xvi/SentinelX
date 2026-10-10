# SentinelX 🔐

**Multi-tenant insider-threat detection SaaS platform** — FastAPI backend, React dashboard, and endpoint agent.

SentinelX ingests endpoint/security events, evaluates them against a policy-aware detection engine (brute force, impossible travel, after-hours access, data exfiltration, USB, shadow IT, and more), and surfaces risk-scored alerts, cases, reports, SIEM forwarding, and notifications through a JWT-secured React dashboard.

## Project Structure

```text
SentinelX/
├── backend/                 # FastAPI SaaS API (multi-tenant, JWT auth, detection engine)
│   ├── app/
│   │   ├── api/             # Route handlers (auth, alerts, cases, employees, policies, dashboard, notifications, siem, reports, sso, events, tenants)
│   │   ├── detection/       # Policy-aware detection engine + risk scoring
│   │   ├── models/          # SQLAlchemy models (Tenant, User, Alert, Case, Employee, Policy, ...)
│   │   ├── schemas/         # Pydantic request/response schemas
│   │   ├── services/        # Notification, SIEM, report, OIDC, alert services
│   │   ├── middleware.py    # Rate limiting + security headers
│   │   └── main.py          # App entrypoint
│   ├── scripts/
│   │   └── migrate_legacy_alerts.py   # One-off import of legacy Logs/alerts.json
│   ├── tests/               # Backend test suite (pytest)
│   └── requirements.txt
├── frontend/                # React + TypeScript operations dashboard (Vite)
│   └── src/
│       ├── api/             # Typed API client
│       ├── auth/            # Auth context + session handling
│       ├── components/      # Layout, charts, UI primitives
│       ├── pages/           # Overview, Alerts, Cases, Employees, Policies, Integrations, Reports, Login
│       └── test/            # Frontend test suite (Vitest)
├── agent/                   # Endpoint event collector + shipper
├── Logs/
│   ├── alerts.json          # Legacy alert seed data (used by the migration script/test)
│   └── auth.log             # Sample auth log for the agent collector
├── docker-compose.yml       # Postgres + Redis + backend stack
└── README.md
```

## Requirements

- Python 3.12+ (`backend/`, `agent/`)
- Node.js 18+ (`frontend/`)
- Postgres 16 + Redis 7 for the full stack (SQLite works for local dev/tests)

## Setup

### 1. Backend

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

API base: `http://127.0.0.1:8000/api/v1` (docs at `/docs`).

### 2. Frontend

```powershell
cd frontend
npm install
npm run dev
```

Dashboard: `http://localhost:5173`. Set `VITE_API_BASE_URL` if the API isn't on the default.

### 3. Full stack (Docker)

```powershell
docker compose up --build
```

### 4. Agent

```powershell
pip install -r agent/requirements.txt
python -m agent.agent
```

## Configuration

The backend is configured via environment variables (see `backend/app/config.py`):

| Setting | Default | Purpose |
|---|---:|---|
| `DATABASE_URL` | `sqlite:///./sentinelx.db` | SQLAlchemy database URL |
| `SECRET_KEY` | dev-only placeholder | JWT signing key — **must** be overridden in production |
| `ENVIRONMENT` | `development` | `development` / `testing` / `production` |
| `CORS_ORIGINS` | `*` | Comma-separated trusted origins |
| `ENABLE_RATE_LIMIT` | `True` | Per-client rate limiting middleware |
| `ENABLE_SECURITY_HEADERS` | `True` | Strict security headers |
| `SSO_ENABLED` | `False` | Enable OIDC single sign-on (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`) |

## Run Tests

Backend (from the project root):

```powershell
python -m pytest backend/tests -q
```

Frontend (from `frontend/`):

```powershell
npm test
```

## Legacy migration

To import the legacy `Logs/alerts.json` seed data into a database tenant:

```powershell
python -m backend.scripts.migrate_legacy_alerts
```

Covered by `backend/tests/test_migration.py` — keep `Logs/alerts.json` in version control so the test stays green.

## Disclaimer

SentinelX is an educational cybersecurity project. Use it only with systems and logs you are authorized to access. Detection results should be reviewed before taking security action.

## Author

**Shreenath Yadav**

GitHub: [@shree-xvi](https://github.com/shree-xvi)
