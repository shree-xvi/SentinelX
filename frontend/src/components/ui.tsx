import type { ReactNode } from "react";

export function Badge({
  value,
  variant,
}: {
  value: string;
  variant?: "severity" | "status";
}) {
  const cls = variant === "status" ? `badge status ${value}` : `badge ${value}`;
  return <span className={cls}>{value}</span>;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div className="loading" role="status">{label}</div>;
}

export function EmptyState({ message }: { message: string }) {
  return <div className="empty">{message}</div>;
}

export function ErrorText({ children }: { children: ReactNode }) {
  return <p className="error-text">{children}</p>;
}

export function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: ReactNode;
  tone?: "critical" | "high";
}) {
  const cls = tone ? `stat ${tone}` : "stat";
  return (
    <div className={cls}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}
