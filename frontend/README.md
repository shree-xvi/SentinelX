# SentinelX Operations Dashboard

A React + TypeScript single-page application for the SentinelX Multi-Tenant
Insider Threat Detection SaaS platform. It provides a security operations
console for triaging alerts, managing investigation cases, reviewing employee
risk profiles, and configuring detection policies.

## Tech Stack

- **React 18** + **TypeScript**
- **Vite** (dev server + build)
- **React Router** (routing & route guards)
- **Axios** (API client with JWT interceptor)
- **Vitest** + **React Testing Library** (unit/component tests)

## Getting Started

### 1. Install dependencies

```bash
cd frontend
npm install
```

### 2. Configure the API base URL

Copy the example env file and adjust if your backend is not on the default
local address:

```bash
cp .env.example .env
```

Default: `VITE_API_BASE_URL=http://localhost:8000/api/v1`

During development, Vite proxies any `/api/*` request to `http://localhost:8000`,
so the backend can run without CORS configuration.

### 3. Run the dev server

```bash
npm run dev
```

Open http://localhost:5173

## Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start the Vite dev server with HMR |
| `npm run build` | Type-check and produce a production build in `dist/` |
| `npm run preview` | Preview the production build locally |
| `npm test` | Run the Vitest suite once |
| `npm run test:watch` | Run tests in watch mode |
| `npm run lint` | Type-check only (no emit) |

## Application Structure

```
src/
├── api/
│   ├── client.ts      # Axios instance, JWT storage & interceptor, api methods
│   └── types.ts       # TypeScript interfaces mirroring backend schemas
├── auth/
│   └── AuthContext.tsx  # Auth provider: login/register/logout, session restore
├── components/
│   ├── AppLayout.tsx    # Sidebar + main outlet shell
│   ├── RequireAuth.tsx  # Route guard redirecting unauthenticated users
│   ├── charts.tsx       # Bar, timeline (stacked), and donut chart primitives
│   └── ui.tsx           # Badge, Stat, Loading, EmptyState, ErrorText
├── pages/
│   ├── LoginPage.tsx
│   ├── RegisterPage.tsx
│   ├── DashboardPage.tsx  # Overview metrics & charts
│   ├── AlertsPage.tsx     # Alert triage, filtering, status, escalate-to-case
│   ├── CasesPage.tsx      # Investigation cases + audit trail notes
│   ├── EmployeesPage.tsx  # Risk roster + UEBA behavioral baseline
│   └── PoliciesPage.tsx   # Detection policy toggles & severity
├── test/                  # Vitest specs and test utilities
├── App.tsx                # Route definitions
├── main.tsx               # React entry point
└── styles.css             # Dark security-operations theme
```

## Authentication Flow

1. On load, if a JWT exists in `localStorage`, `AuthContext` calls `/auth/me`
   to restore the session.
2. Login and Registration store the returned `access_token` and populate the
   user profile.
3. The Axios request interceptor attaches `Authorization: Bearer <token>` to
   every request.
4. A `401` response clears the stored token so the route guard redirects to
   the login page.

## Testing

The suite covers pure utilities (formatting, error normalization), chart
rendering, and page interactions (login error handling, alert status updates,
case notes, policy toggles, dashboard metrics). API calls are mocked via
`vi.spyOn` on the `api` client, so no live backend is required.

```bash
npm test
```

## Notes

- The dashboard consumes the FastAPI backend defined in `../backend`.
- Chart visualizations are dependency-free (pure CSS/SVG) to keep the bundle
  small and the tests deterministic.
