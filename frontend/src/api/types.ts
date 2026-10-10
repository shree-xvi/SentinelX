// TypeScript interfaces mirroring the SentinelX FastAPI backend schemas.

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "New" | "Investigating" | "Resolved" | "Closed";
export type CaseStatus = "New" | "Investigating" | "Escalated" | "Resolved" | "Closed";
export type Priority = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type UserRole = "analyst" | "admin" | "super_admin";

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  tenant_id: string;
  role: string;
  email: string;
}

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
}

export interface Tenant {
  id: string;
  name: string;
  domain: string;
  plan: string;
  business_hours_start: number;
  business_hours_end: number;
  timezone: string;
  created_at: string;
}

export interface TenantUpdate {
  name?: string;
  business_hours_start?: number;
  business_hours_end?: number;
  timezone?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  raw_key?: string | null;
}

export interface Employee {
  id: string;
  tenant_id: string;
  employee_id: string;
  name: string;
  email: string | null;
  department: string | null;
  title: string | null;
  risk_score: number;
  risk_level: RiskLevel;
  last_activity: string | null;
  created_at: string;
}

export interface EmployeeCreate {
  employee_id: string;
  name: string;
  email?: string;
  department?: string;
  title?: string;
}

export interface Alert {
  id: string;
  tenant_id: string;
  employee_id: string | null;
  alert_type: string;
  severity: Severity;
  risk_score: number;
  risk_level: RiskLevel;
  source_ip: string | null;
  fingerprint: string;
  status: AlertStatus;
  evidence: Record<string, unknown>;
  detected_at: string;
  created_at: string;
}

export interface EventRecord {
  id: string;
  tenant_id: string;
  employee_id: string | null;
  event_type: string;
  source: string;
  source_ip: string | null;
  username: string | null;
  event_data: Record<string, unknown>;
  timestamp: string;
  created_at: string;
}

export interface CaseNote {
  id: string;
  case_id: string;
  author_id: string | null;
  note: string;
  action_type: string;
  created_at: string;
}

export interface Case {
  id: string;
  tenant_id: string;
  alert_id: string | null;
  assigned_to: string | null;
  title: string;
  description: string | null;
  status: CaseStatus;
  priority: Priority;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  notes: CaseNote[];
}

export interface CaseCreate {
  alert_id?: string | null;
  title: string;
  description?: string;
  priority?: Priority;
  assigned_to?: string | null;
}

export interface Policy {
  id: string;
  tenant_id: string;
  name: string;
  rule_type: string;
  description: string | null;
  severity: Severity;
  enabled: boolean;
  conditions: Record<string, unknown>;
  created_at: string;
}

export interface PolicyCreate {
  name: string;
  rule_type: string;
  description?: string;
  severity?: Severity;
  enabled?: boolean;
  conditions?: Record<string, unknown>;
}

export interface PolicyUpdate {
  name?: string;
  description?: string;
  severity?: Severity;
  enabled?: boolean;
  conditions?: Record<string, unknown>;
}

export interface DashboardOverview {
  total_alerts: number;
  average_risk_score: number;
  severities: Record<Severity, number>;
  risk_levels: Record<string, number>;
  cases: {
    open: number;
    resolved: number;
  };
}

export interface TopRiskEmployee {
  id: string;
  employee_id: string;
  name: string;
  department: string;
  risk_score: number;
  risk_level: RiskLevel;
  last_activity: string | null;
}

export interface TimelinePoint {
  date: string;
  total: number;
  by_severity: Record<string, number>;
}

export interface NotificationChannel {
  id: string;
  tenant_id: string;
  name: string;
  channel_type: string;
  target: string;
  min_severity: string;
  enabled: boolean;
  created_at: string;
}

export interface NotificationChannelCreate {
  name: string;
  channel_type?: string;
  target: string;
  min_severity?: string;
  enabled?: boolean;
  secret?: string;
}

export interface NotificationLog {
  id: string;
  channel_id: string | null;
  alert_id: string | null;
  status: string;
  response_status: number | null;
  error: string | null;
  created_at: string;
}

export interface SiemIntegration {
  id: string;
  tenant_id: string;
  name: string;
  provider: string;
  endpoint: string;
  format: string;
  forward_scope: string;
  min_severity: string;
  enabled: boolean;
  last_status: string | null;
  last_error: string | null;
  last_sent_at: string | null;
  created_at: string;
}

export interface SiemIntegrationCreate {
  name: string;
  provider?: string;
  endpoint: string;
  format?: string;
  auth_token?: string;
  forward_scope?: string;
  min_severity?: string;
  enabled?: boolean;
}

export interface ReportSummary {
  tenant: { id: string; name: string; domain: string };
  period_days: number;
  generated_at: string;
  alerts: {
    total: number;
    by_severity: Record<string, number>;
    by_type: Record<string, number>;
    rows: Record<string, unknown>[];
  };
  cases: {
    total: number;
    open: number;
    rows: Record<string, unknown>[];
  };
  employees: {
    total: number;
    high_risk: number;
    rows: Record<string, unknown>[];
  };
}

export interface SsoConfig {
  enabled: boolean;
  authorization_url?: string | null;
  state?: string | null;
  nonce?: string | null;
}
