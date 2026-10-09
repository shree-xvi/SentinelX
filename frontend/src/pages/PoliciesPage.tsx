import { useCallback, useEffect, useState } from "react";
import { api, toApiError } from "../api/client";
import type { Policy } from "../api/types";
import { isAdminRole, useAuth } from "../auth/AuthContext";
import { Badge, EmptyState, ErrorText, Loading } from "../components/ui";

export function PoliciesPage() {
  const { role } = useAuth();
  const canManage = isAdminRole(role);

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .listPolicies()
      .then((data) => setPolicies(data))
      .catch((err) => setError(toApiError(err).message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggleEnabled = async (policy: Policy) => {
    setActionError(null);
    try {
      await api.updatePolicy(policy.id, { enabled: !policy.enabled });
      setPolicies((prev) =>
        prev.map((p) => (p.id === policy.id ? { ...p, enabled: !p.enabled } : p))
      );
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const changeSeverity = async (policy: Policy, severity: Policy["severity"]) => {
    setActionError(null);
    try {
      await api.updatePolicy(policy.id, { severity });
      setPolicies((prev) => prev.map((p) => (p.id === policy.id ? { ...p, severity } : p)));
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const enabledCount = policies.filter((p) => p.enabled).length;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Detection Policies</h1>
          <div className="subtitle">Configure which threat rules run against your telemetry</div>
        </div>
      </div>

      {actionError && <ErrorText>{actionError}</ErrorText>}
      {error && <ErrorText>{error}</ErrorText>}

      <p className="muted" style={{ marginTop: 0 }}>
        {enabledCount} of {policies.length} rules enabled.
      </p>

      {loading ? (
        <Loading />
      ) : policies.length === 0 ? (
        <EmptyState message="No detection policies configured." />
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Conditions</th>
                <th>Enabled</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <tr key={policy.id}>
                  <td>
                    {policy.name}
                    {policy.description && (
                      <div className="muted" style={{ fontSize: 12, fontWeight: 400 }}>
                        {policy.description}
                      </div>
                    )}
                  </td>
                  <td className="mono">{policy.rule_type}</td>
                  <td>
                    {canManage ? (
                      <select
                        value={policy.severity}
                        onChange={(e) => changeSeverity(policy, e.target.value as Policy["severity"])}
                        aria-label={`Severity for ${policy.rule_type}`}
                        style={{ width: 120 }}
                      >
                        <option value="LOW">LOW</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="HIGH">HIGH</option>
                        <option value="CRITICAL">CRITICAL</option>
                      </select>
                    ) : (
                      <Badge value={policy.severity} />
                    )}
                  </td>
                  <td className="mono" style={{ maxWidth: 220, wordBreak: "break-word" }}>
                    {JSON.stringify(policy.conditions)}
                  </td>
                  <td>
                    <button
                      className={`toggle${policy.enabled ? " on" : ""}`}
                      role="switch"
                      aria-checked={policy.enabled}
                      aria-label={`Toggle ${policy.rule_type}`}
                      disabled={!canManage}
                      onClick={() => toggleEnabled(policy)}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!canManage && (
            <p className="muted" style={{ marginBottom: 0 }}>
              Only administrators can modify detection policies.
            </p>
          )}
        </div>
      )}
    </>
  );
}
