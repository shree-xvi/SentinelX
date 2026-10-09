import type { TimelinePoint } from "../api/types";
import { formatDateShort } from "../utils/format";

/** Horizontal bar chart for categorical counts (e.g. alerts by rule). */
export function BarChart({
  data,
}: {
  data: Array<{ label: string; value: number }>;
}) {
  const max = Math.max(1, ...data.map((d) => d.value));
  if (data.length === 0) {
    return <div className="empty">No data available.</div>;
  }
  return (
    <div className="bar-chart" role="img" aria-label="Bar chart">
      {data.map((d) => (
        <div className="bar-row" key={d.label}>
          <span className="bar-label" title={d.label}>
            {d.label}
          </span>
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{ width: `${Math.round((d.value / max) * 100)}%` }}
            />
          </div>
          <span className="bar-value">{d.value}</span>
        </div>
      ))}
    </div>
  );
}

const SEVERITY_STACK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

/** Stacked column chart of daily alert counts by severity. */
export function TimelineChart({ data }: { data: TimelinePoint[] }) {
  if (data.length === 0) {
    return <div className="empty">No alerts in this period.</div>;
  }
  const max = Math.max(1, ...data.map((d) => d.total));
  return (
    <div className="timeline" role="img" aria-label="Alert timeline">
      {data.map((point) => (
        <div className="col" key={point.date}>
          <div
            className="stack"
            style={{ height: `${Math.round((point.total / max) * 100)}%` }}
            title={`${point.date}: ${point.total} alerts`}
          >
            {SEVERITY_STACK_ORDER.map((sev) => {
              const count = point.by_severity?.[sev] ?? 0;
              if (!count) return null;
              return (
                <div
                  key={sev}
                  className={`seg ${sev}`}
                  style={{ flex: count }}
                  title={`${sev}: ${count}`}
                />
              );
            })}
          </div>
          <span className="xlabel">{formatDateShort(point.date)}</span>
        </div>
      ))}
    </div>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ff7373",
  HIGH: "#ffab5e",
  MEDIUM: "#ffca6a",
  LOW: "#76dfae",
};

/** Donut chart for severity distribution. */
export function DonutChart({
  data,
}: {
  data: Record<string, number>;
}) {
  const entries = Object.entries(data).filter(([, v]) => v > 0);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);
  if (total === 0) {
    return <div className="empty">No alerts to summarize.</div>;
  }

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="donut">
      <svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="Severity distribution">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="#26334b" strokeWidth="16" />
        {entries.map(([sev, count]) => {
          const fraction = count / total;
          const dash = fraction * circumference;
          const circle = (
            <circle
              key={sev}
              cx="70"
              cy="70"
              r={radius}
              fill="none"
              stroke={SEVERITY_COLORS[sev] ?? "#62b4ff"}
              strokeWidth="16"
              strokeDasharray={`${dash} ${circumference - dash}`}
              strokeDashoffset={-offset}
            />
          );
          offset += dash;
          return circle;
        })}
        <text
          x="70"
          y="70"
          textAnchor="middle"
          dominantBaseline="central"
          fill="#e8eef8"
          fontSize="24"
          fontWeight="700"
          transform="rotate(90 70 70)"
        >
          {total}
        </text>
      </svg>
      <div className="legend">
        {entries.map(([sev, count]) => (
          <div className="item" key={sev}>
            <span className="swatch" style={{ background: SEVERITY_COLORS[sev] ?? "#62b4ff" }} />
            <span>{sev}</span>
            <span className="muted">{count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
