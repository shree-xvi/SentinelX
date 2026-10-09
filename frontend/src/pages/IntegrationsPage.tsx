import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, toApiError } from "../api/client";
import type { NotificationChannel, NotificationLog, SiemIntegration } from "../api/types";
import { isAdminRole, useAuth } from "../auth/AuthContext";
import { Badge, EmptyState, ErrorText, Loading } from "../components/ui";

const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export function IntegrationsPage() {
  const { role } = useAuth();
  const canManage = isAdminRole(role);

  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [integrations, setIntegrations] = useState<SiemIntegration[]>([]);
  const [logs, setLogs] = useState<NotificationLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);

  const [channelName, setChannelName] = useState("");
  const [channelType, setChannelType] = useState("webhook");
  const [channelTarget, setChannelTarget] = useState("");
  const [channelSeverity, setChannelSeverity] = useState("HIGH");

  const [siemName, setSiemName] = useState("");
  const [siemProvider, setSiemProvider] = useState("splunk_hec");
  const [siemEndpoint, setSiemEndpoint] = useState("");
  const [siemFormat, setSiemFormat] = useState("json");

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([api.listNotificationChannels(), api.listSiemIntegrations(), api.listNotificationLogs(25)])
      .then(([c, s, l]) => {
        setChannels(c);
        setIntegrations(s);
        setLogs(l);
      })
      .catch((err) => setError(toApiError(err).message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const createChannel = async (e: FormEvent) => {
    e.preventDefault();
    setActionError(null);
    setActionInfo(null);
    try {
      const created = await api.createNotificationChannel({
        name: channelName,
        channel_type: channelType,
        target: channelTarget,
        min_severity: channelSeverity,
      });
      setChannels((prev) => [created, ...prev]);
      setChannelName("");
      setChannelTarget("");
      setActionInfo(`Channel "${created.name}" created.`);
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const toggleChannel = async (channel: NotificationChannel) => {
    setActionError(null);
    try {
      const updated = await api.updateNotificationChannel(channel.id, { enabled: !channel.enabled });
      setChannels((prev) => prev.map((c) => (c.id === channel.id ? updated : c)));
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const deleteChannel = async (channel: NotificationChannel) => {
    setActionError(null);
    try {
      await api.deleteNotificationChannel(channel.id);
      setChannels((prev) => prev.filter((c) => c.id !== channel.id));
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const testChannel = async (channel: NotificationChannel) => {
    setActionError(null);
    setActionInfo(null);
    try {
      const log = await api.testNotificationChannel(channel.id);
      setLogs((prev) => [log, ...prev].slice(0, 25));
      setActionInfo(`Test sent to "${channel.name}" — status: ${log.status}.`);
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const createSiem = async (e: FormEvent) => {
    e.preventDefault();
    setActionError(null);
    setActionInfo(null);
    try {
      const created = await api.createSiemIntegration({
        name: siemName,
        provider: siemProvider,
        endpoint: siemEndpoint,
        format: siemFormat,
      });
      setIntegrations((prev) => [created, ...prev]);
      setSiemName("");
      setSiemEndpoint("");
      setActionInfo(`SIEM integration "${created.name}" created.`);
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const toggleSiem = async (integration: SiemIntegration) => {
    setActionError(null);
    try {
      const updated = await api.updateSiemIntegration(integration.id, { enabled: !integration.enabled });
      setIntegrations((prev) => prev.map((i) => (i.id === integration.id ? updated : i)));
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const deleteSiem = async (integration: SiemIntegration) => {
    setActionError(null);
    try {
      await api.deleteSiemIntegration(integration.id);
      setIntegrations((prev) => prev.filter((i) => i.id !== integration.id));
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const testSiem = async (integration: SiemIntegration) => {
    setActionError(null);
    setActionInfo(null);
    try {
      const result = await api.testSiemIntegration(integration.id);
      setActionInfo(
        result.ok
          ? `Test alert forwarded to "${integration.name}" successfully.`
          : `Test failed for "${integration.name}": ${result.error ?? "unknown error"}`
      );
      load();
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };



  return (
    <>
      <div className="topbar">
        <div>
          <h1>Integrations</h1>
          <div className="subtitle">Notifications, SIEM forwarding, and delivery status</div>
        </div>
        <button className="btn small" onClick={load}>
          Refresh
        </button>
      </div>

      {actionError && <ErrorText>{actionError}</ErrorText>}
      {actionInfo && <p className="muted">{actionInfo}</p>}
      {error && <ErrorText>{error}</ErrorText>}

      {loading ? (
        <Loading />
      ) : (
        <>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Notification channels</h3>
            {channels.length === 0 ? (
              <EmptyState message="No notification channels configured." />
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Min severity</th>
                    <th>Enabled</th>
                    {canManage && <th>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {channels.map((channel) => (
                    <tr key={channel.id}>
                      <td>{channel.name}</td>
                      <td className="mono">{channel.channel_type}</td>
                      <td className="mono" style={{ maxWidth: 220, wordBreak: "break-word" }}>
                        {channel.target}
                      </td>
                      <td>
                        <Badge value={channel.min_severity} />
                      </td>
                      <td>
                        <button
                          className={`toggle${channel.enabled ? " on" : ""}`}
                          role="switch"
                          aria-checked={channel.enabled}
                          aria-label={`Toggle ${channel.name}`}
                          disabled={!canManage}
                          onClick={() => toggleChannel(channel)}
                        />
                      </td>
                      {canManage && (
                        <td>
                          <div style={{ display: "flex", gap: 8 }}>
                            <button className="btn small" onClick={() => testChannel(channel)}>
                              Send test
                            </button>
                            <button className="btn small" onClick={() => deleteChannel(channel)}>
                              Delete
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {canManage && (
              <form onSubmit={createChannel} style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                <input
                  placeholder="Channel name"
                  value={channelName}
                  onChange={(e) => setChannelName(e.target.value)}
                  required
                />
                <select value={channelType} onChange={(e) => setChannelType(e.target.value)} aria-label="Channel type">
                  <option value="webhook">webhook</option>
                  <option value="slack">slack</option>
                  <option value="email">email</option>
                </select>
                <input
                  placeholder="Target URL or address"
                  value={channelTarget}
                  onChange={(e) => setChannelTarget(e.target.value)}
                  required
                  style={{ minWidth: 220 }}
                />
                <select
                  value={channelSeverity}
                  onChange={(e) => setChannelSeverity(e.target.value)}
                  aria-label="Minimum severity"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
                <button className="btn primary small" type="submit">
                  Add channel
                </button>
              </form>
            )}
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>SIEM forwarding</h3>
            {integrations.length === 0 ? (
              <EmptyState message="No SIEM integrations configured." />
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Provider</th>
                    <th>Format</th>
                    <th>Last status</th>
                    <th>Enabled</th>
                    {canManage && <th>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {integrations.map((integration) => (
                    <tr key={integration.id}>
                      <td>
                        {integration.name}
                        <div className="muted mono" style={{ fontSize: 12 }}>
                          {integration.endpoint}
                        </div>
                      </td>
                      <td className="mono">{integration.provider}</td>
                      <td className="mono">{integration.format.toUpperCase()}</td>
                      <td>{integration.last_status ?? "—"}</td>
                      <td>
                        <button
                          className={`toggle${integration.enabled ? " on" : ""}`}
                          role="switch"
                          aria-checked={integration.enabled}
                          aria-label={`Toggle ${integration.name}`}
                          disabled={!canManage}
                          onClick={() => toggleSiem(integration)}
                        />
                      </td>
                      {canManage && (
                        <td>
                          <div style={{ display: "flex", gap: 8 }}>
                            <button className="btn small" onClick={() => testSiem(integration)}>
                              Send test
                            </button>
                            <button className="btn small" onClick={() => deleteSiem(integration)}>
                              Delete
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {canManage && (
              <form onSubmit={createSiem} style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                <input
                  placeholder="Integration name"
                  value={siemName}
                  onChange={(e) => setSiemName(e.target.value)}
                  required
                />
                <select
                  value={siemProvider}
                  onChange={(e) => setSiemProvider(e.target.value)}
                  aria-label="SIEM provider"
                >
                  <option value="splunk_hec">splunk_hec</option>
                  <option value="webhook">webhook</option>
                  <option value="sentinel">sentinel</option>
                  <option value="qradar">qradar</option>
                </select>
                <input
                  placeholder="Collector endpoint"
                  value={siemEndpoint}
                  onChange={(e) => setSiemEndpoint(e.target.value)}
                  required
                  style={{ minWidth: 220 }}
                />
                <select value={siemFormat} onChange={(e) => setSiemFormat(e.target.value)} aria-label="Payload format">
                  <option value="json">JSON</option>
                  <option value="cef">CEF</option>
                </select>
                <button className="btn primary small" type="submit">
                  Add integration
                </button>
              </form>
            )}
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Delivery log</h3>
            {logs.length === 0 ? (
              <EmptyState message="No notification deliveries yet." />
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Channel</th>
                    <th>Status</th>
                    <th>HTTP</th>
                    <th>Error</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id}>
                      <td className="mono">{log.channel_id ?? "—"}</td>
                      <td>
                        <Badge value={log.status} variant="status" />
                      </td>
                      <td>{log.response_status ?? "—"}</td>
                      <td className="muted">{log.error ?? "—"}</td>
                      <td className="muted">{new Date(log.created_at).toLocaleString()}</td>
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


