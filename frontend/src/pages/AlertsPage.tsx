import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, toApiError } from "../api/client";
import type { Alert, AlertStatus } from "../api/types";
import { Badge, EmptyState, ErrorText, Loading } from "../components/ui";
import { formatDateTime, humanizeRuleType, SEVERITY_ORDER } from "../utils/format";

const STATUS_OPTIONS: AlertStatus[] = ["New", "Investigating", "Resolved", "Closed"];

export function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<Alert | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .listAlerts({
        severity: severity || undefined,
        status: status || undefined,
        limit: 100,
      })
      .then((data) => setAlerts(data))
      .catch((err) => setError(toApiError(err).message))
      .finally(() => setLoading(false));
  }, [severity, status]);

  useEffect(() => {
    load();
  }, [load]);

  const changeStatus = async (alert: Alert, nextStatus: AlertStatus) => {
    setActionError(null);
    try {
      const updated = await api.updateAlertStatus(alert.id, nextStatus);
      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setSelected((cur) => (cur && cur.id === updated.id ? updated : cur));
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const openCase = (alert: Alert) => {
    navigate("/cases", {
      state: {
        fromAlert: alert.id,
        title: `${humanizeRuleType(alert.alert_type)}: ${alert.source_ip ?? alert.id.slice(0, 8)}`,
      },
    });
  };

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Threat Alerts</h1>
          <div className="subtitle">Triage and investigate detection alerts</div>
        </div>
      </div>

      <div className="toolbar">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          aria-label="Filter by severity"
          style={{ width: 160 }}
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          aria-label="Filter by status"
          style={{ width: 160 }}
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <div className="grow" />
        <button className="btn" onClick={load}>
          Refresh
        </button>
      </div>

      {error && <ErrorText>{error}</ErrorText>}
      {loading ? (
        <Loading />
      ) : alerts.length === 0 ? (
        <EmptyState message="No alerts match the current filters." />
      ) : (
        <div className="grid cols-2">
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id} className="clickable" onClick={() => setSelected(alert)}>
                    <td>{humanizeRuleType(alert.alert_type)}</td>
                    <td>
                      <Badge value={alert.severity} />
                    </td>
                    <td>{alert.risk_score.toFixed(1)}</td>
                    <td>
                      <Badge value={alert.status} variant="status" />
                    </td>
                    <td className="muted">{formatDateTime(alert.detected_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <AlertDetail
            alert={selected}
            actionError={actionError}
            onChangeStatus={changeStatus}
            onEscalate={openCase}
          />
        </div>
      )}
    </>
  );

function AlertDetail({
  alert,
  actionError,
  onChangeStatus,
  onEscalate,
}: {
  alert: Alert | null;
  actionError: string | null;
  onChangeStatus: (alert: Alert, status: AlertStatus) => void;
  onEscalate: (alert: Alert) => void;
}) {
  if (!alert) {
    return (
      <div className="card">
        <EmptyState message="Select an alert to view details and evidence." />
      </div>
    );
  }
  return (
    <div className="card">
      <div className="row-between" style={{ marginBottom: 10 }}>
        <h3 style={{ margin: 0 }}>{humanizeRuleType(alert.alert_type)}</h3>
        <Badge value={alert.severity} />
      </div>
      <dl className="kv" style={{ marginBottom: 14 }}>
        <dt>Status</dt>
        <dd>
          <Badge value={alert.status} variant="status" />
        </dd>
        <dt>Risk</dt>
        <dd>
          {alert.risk_score.toFixed(1)} ({alert.risk_level})
        </dd>
        <dt>Source IP</dt>
        <dd className="mono">{alert.source_ip ?? "—"}</dd>
        <dt>Detected</dt>
        <dd>{formatDateTime(alert.detected_at)}</dd>
        <dt>Fingerprint</dt>
        <dd className="mono" style={{ wordBreak: "break-all" }}>
          {alert.fingerprint.slice(0, 24)}…
        </dd>
      </dl>

      <h4 className="muted" style={{ margin: "0 0 6px" }}>
        Evidence
      </h4>
      <pre className="evidence">{JSON.stringify(alert.evidence, null, 2)}</pre>

      {actionError && <ErrorText>{actionError}</ErrorText>}

      <div style={{ marginTop: 14 }}>
        <div className="muted" style={{ fontSize: 13, marginBottom: 6 }}>
          Update status
        </div>
        <div className="btn-row">
          {STATUS_OPTIONS.map((s) => (
            <button
              key={s}
              className={`btn small${alert.status === s ? " primary" : ""}`}
              disabled={alert.status === s}
              onClick={() => onChangeStatus(alert, s)}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div style={{ marginTop: 14 }}>
        <button className="btn" onClick={() => onEscalate(alert)}>
          Escalate to case
        </button>
      </div>
    </div>
  );
}

}
