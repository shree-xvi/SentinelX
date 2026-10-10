import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, toApiError } from "../api/client";
import type { DashboardOverview, TimelinePoint, TopRiskEmployee } from "../api/types";
import { BarChart, DonutChart, TimelineChart } from "../components/charts";
import { Badge, EmptyState, Loading, Stat } from "../components/ui";
import { humanizeRuleType, timeAgo } from "../utils/format";

export function DashboardPage() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [topRisks, setTopRisks] = useState<TopRiskEmployee[]>([]);
  const [ruleStats, setRuleStats] = useState<Record<string, number>>({});
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      api.dashboardOverview(),
      api.dashboardTopRisks(),
      api.dashboardRuleStats(),
      api.dashboardTimeline(7),
    ])
      .then(([ov, risks, rules, tl]) => {
        if (cancelled) return;
        setOverview(ov);
        setTopRisks(risks);
        setRuleStats(rules);
        setTimeline(tl);
      })
      .catch((err) => {
        if (!cancelled) setError(toApiError(err).message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <Loading label="Loading overview…" />;
  if (error) return <div className="form-error">{error}</div>;

  const ruleData = Object.entries(ruleStats)
    .map(([rule, count]) => ({ label: humanizeRuleType(rule), value: count }))
    .sort((a, b) => b.value - a.value);

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Security Overview</h1>
          <div className="subtitle">Insider threat posture for your organization</div>
        </div>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat label="Total Alerts" value={overview?.total_alerts ?? 0} />
        <Stat
          label="Critical"
          value={overview?.severities?.CRITICAL ?? 0}
          tone="critical"
        />
        <Stat label="High" value={overview?.severities?.HIGH ?? 0} tone="high" />
        <Stat label="Avg Risk Score" value={overview?.average_risk_score?.toFixed(1) ?? "0.0"} />
      </div>

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3>Severity Distribution</h3>
          <DonutChart data={overview?.severities ?? {}} />
        </div>
        <div className="card">
          <h3>Open Cases</h3>
          <div style={{ fontSize: 40, fontWeight: 700 }}>{overview?.cases?.open ?? 0}</div>
          <div className="muted">Resolved: {overview?.cases?.resolved ?? 0}</div>
        </div>
        <div className="card">
          <h3>Risk Levels</h3>
          <BarChart
            data={Object.entries(overview?.risk_levels ?? {})
              .filter(([, v]) => v > 0)
              .sort((a, b) => b[1] - a[1])
              .map(([level, count]) => ({ label: level, value: count }))}
          />
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h3>Alert Timeline (last 7 days)</h3>
        <TimelineChart data={timeline} />
      </div>

      <div className="grid cols-2">
        <div className="card">
          <div className="row-between" style={{ marginBottom: 8 }}>
            <h3 style={{ margin: 0 }}>Top Risk Employees</h3>
            <Link to="/employees" className="small">
              View all
            </Link>
          </div>
          {topRisks.length === 0 ? (
            <EmptyState message="No monitored employees yet." />
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Employee</th>
                  <th>Risk</th>
                  <th>Score</th>
                  <th>Last Active</th>
                </tr>
              </thead>
              <tbody>
                {topRisks.slice(0, 8).map((emp) => (
                  <tr key={emp.id}>
                    <td>
                      {emp.name}
                      <div className="muted" style={{ fontSize: 12 }}>
                        {emp.department}
                      </div>
                    </td>
                    <td>
                      <Badge value={emp.risk_level} />
                    </td>
                    <td>{emp.risk_score.toFixed(1)}</td>
                    <td className="muted">{timeAgo(emp.last_activity)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <h3>Detections by Rule</h3>
          {ruleData.length === 0 ? (
            <EmptyState message="No detection activity yet." />
          ) : (
            <BarChart data={ruleData} />
          )}
        </div>
      </div>
    </>
  );
}
