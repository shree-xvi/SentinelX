import { useCallback, useEffect, useState } from "react";
import { api, getStoredToken, toApiError } from "../api/client";
import type { ReportSummary } from "../api/types";
import { ErrorText, Loading, Stat } from "../components/ui";

const DAY_OPTIONS = [7, 30, 90];

export function ReportsPage() {
  const [days, setDays] = useState(30);
  const [summary, setSummary] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    (d: number) => {
      setLoading(true);
      setError(null);
      api
        .reportSummary(d)
        .then((data) => setSummary(data))
        .catch((err) => setError(toApiError(err).message))
        .finally(() => setLoading(false));
    },
    []
  );

  useEffect(() => {
    load(days);
  }, [days, load]);

  const csvHref = () => {
    const base = import.meta.env?.VITE_API_BASE_URL ?? "/api/v1";
    return `${base}/reports/summary?format=csv&days=${days}`;
  };

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Reports</h1>
          <div className="subtitle">Security posture summary and CSV export</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Report period">
            {DAY_OPTIONS.map((d) => (
              <option key={d} value={d}>
                Last {d} days
              </option>
            ))}
          </select>
          <a
            className="btn small"
            href={csvHref()}
            onClick={(e) => {
              const token = getStoredToken();
              if (!token) return;
              e.preventDefault();
              fetch(csvHref(), { headers: { Authorization: `Bearer ${token}` } })
                .then((r) => r.blob())
                .then((blob) => {
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `sentinelx_report_${days}d.csv`;
                  a.click();
                  URL.revokeObjectURL(url);
                });
            }}
          >
            Download CSV
          </a>
        </div>
      </div>

      {error && <ErrorText>{error}</ErrorText>}

      {loading ? (
        <Loading />
      ) : !summary ? (
        <p className="muted">No report data.</p>
      ) : (
        <>
          <div className="stats">
            <Stat label="Alerts in period" value={summary.alerts.total} />
            <Stat label="Open cases" value={summary.cases.open} tone="high" />
            <Stat label="Employees tracked" value={summary.employees.total} />
            <Stat label="High-risk employees" value={summary.employees.high_risk} tone="critical" />
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Alerts by severity</h3>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {Object.entries(summary.alerts.by_severity).map(([sev, count]) => (
                <span key={sev} className={`badge ${sev}`}>
                  {sev}: {count}
                </span>
              ))}
              {Object.keys(summary.alerts.by_severity).length === 0 && (
                <span className="muted">No alerts in this period.</span>
              )}
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Alerts by type</h3>
            {Object.keys(summary.alerts.by_type).length === 0 ? (
              <span className="muted">No alerts in this period.</span>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(summary.alerts.by_type).map(([rule, count]) => (
                    <tr key={rule}>
                      <td className="mono">{rule}</td>
                      <td>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </>
  );
}
