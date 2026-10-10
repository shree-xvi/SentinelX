import axios, { AxiosError, AxiosInstance } from "axios";
import type {
  Alert,
  AlertStatus,
  ApiKey,
  Case,
  CaseCreate,
  CaseNote,
  DashboardOverview,
  Employee,
  EmployeeCreate,
  NotificationChannel,
  NotificationChannelCreate,
  NotificationLog,
  Policy,
  PolicyCreate,
  PolicyUpdate,
  ReportSummary,
  SiemIntegration,
  SiemIntegrationCreate,
  SsoConfig,
  Tenant,
  TenantUpdate,
  TimelinePoint,
  TokenResponse,
  TopRiskEmployee,
  User,
} from "./types";

const TOKEN_STORAGE_KEY = "sentinelx_access_token";

const BASE_URL =
  (import.meta.env?.VITE_API_BASE_URL as string | undefined) ?? "/api/v1";

/** Read the persisted JWT from local storage. */
export function getStoredToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

/** Persist (or clear) the JWT in local storage. */
export function setStoredToken(token: string | null): void {
  try {
    if (token) {
      window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Storage unavailable (private mode); degrade gracefully.
  }
}

/** Normalized error shape for the UI layer. */
export interface ApiError {
  message: string;
  status: number;
}

function toApiError(error: unknown): ApiError {
  // Already a normalized ApiError (e.g. re-thrown from the response
  // interceptor) — return as-is so messages are not double-wrapped.
  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    "status" in error &&
    typeof (error as ApiError).message === "string" &&
    typeof (error as ApiError).status === "number"
  ) {
    return error as ApiError;
  }
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<{ detail?: string | { msg?: string }[] }>;
    const detail = axiosError.response?.data?.detail;
    let message: string;
    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail) && detail.length > 0) {
      message = detail[0]?.msg ?? "Validation error.";
    } else {
      message = axiosError.message || "Unexpected network error.";
    }
    return { message, status: axiosError.response?.status ?? 0 };
  }
  return { message: "Unexpected error.", status: 0 };
}

const client: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: { "Content-Type": "application/json" },
});

// Attach the bearer token to every outgoing request when present.
client.interceptors.request.use((config) => {
  const token = getStoredToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On a 401, drop the stale token so the auth context can redirect to login.
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      setStoredToken(null);
    }
    return Promise.reject(toApiError(error));
  }
);

function buildQuery(params: Record<string, unknown>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.append(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}


export const api = {
  // ---- Authentication -----------------------------------------------------
  register(payload: {
    company_name: string;
    domain: string;
    full_name: string;
    email: string;
    password: string;
  }): Promise<TokenResponse> {
    return client.post<TokenResponse>("/auth/register", payload).then((r) => r.data);
  },

  login(payload: { email: string; password: string }): Promise<TokenResponse> {
    return client.post<TokenResponse>("/auth/login", payload).then((r) => r.data);
  },

  me(): Promise<User> {
    return client.get<User>("/auth/me").then((r) => r.data);
  },

  listApiKeys(): Promise<ApiKey[]> {
    return client.get<ApiKey[]>("/auth/api-keys").then((r) => r.data);
  },

  createApiKey(name: string): Promise<ApiKey> {
    return client.post<ApiKey>("/auth/api-keys", { name }).then((r) => r.data);
  },

  // ---- Tenant -------------------------------------------------------------
  getTenant(): Promise<Tenant> {
    return client.get<Tenant>("/tenant").then((r) => r.data);
  },

  updateTenant(payload: TenantUpdate): Promise<Tenant> {
    return client.put<Tenant>("/tenant", payload).then((r) => r.data);
  },

  // ---- Employees ----------------------------------------------------------
  listEmployees(
    params: {
      search?: string;
      department?: string;
      min_risk?: number;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Employee[]> {
    return client.get<Employee[]>(`/employees${buildQuery(params)}`).then((r) => r.data);
  },

  createEmployee(payload: EmployeeCreate): Promise<Employee> {
    return client.post<Employee>("/employees", payload).then((r) => r.data);
  },

  getEmployeeBaseline(
    employeeId: string
  ): Promise<{
    employee_id: string;
    name: string;
    overall_score: number;
    risk_level: string;
    baseline: Record<string, unknown>;
    last_calculated: string | null;
  }> {
    return client.get(`/employees/${employeeId}/baseline`).then((r) => r.data);
  },

  // ---- Alerts -------------------------------------------------------------
  listAlerts(
    params: {
      severity?: string;
      status?: string;
      alert_type?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Alert[]> {
    return client.get<Alert[]>(`/alerts${buildQuery(params)}`).then((r) => r.data);
  },

  getAlert(alertId: string): Promise<Alert> {
    return client.get<Alert>(`/alerts/${alertId}`).then((r) => r.data);
  },

  updateAlertStatus(alertId: string, status: AlertStatus): Promise<Alert> {
    return client.patch<Alert>(`/alerts/${alertId}`, { status }).then((r) => r.data);
  },

  // ---- Cases --------------------------------------------------------------
  listCases(
    params: {
      status?: string;
      priority?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Case[]> {
    return client.get<Case[]>(`/cases${buildQuery(params)}`).then((r) => r.data);
  },

  getCase(caseId: string): Promise<Case> {
    return client.get<Case>(`/cases/${caseId}`).then((r) => r.data);
  },

  createCase(payload: CaseCreate): Promise<Case> {
    return client.post<Case>("/cases", payload).then((r) => r.data);
  },

  updateCase(
    caseId: string,
    payload: { status?: string; priority?: string; assigned_to?: string }
  ): Promise<Case> {
    return client.patch<Case>(`/cases/${caseId}`, payload).then((r) => r.data);
  },

  addCaseNote(
    caseId: string,
    note: string,
    actionType = "comment"
  ): Promise<CaseNote> {
    return client
      .post<CaseNote>(`/cases/${caseId}/notes`, { note, action_type: actionType })
      .then((r) => r.data);
  },

  // ---- Policies -----------------------------------------------------------
  listPolicies(): Promise<Policy[]> {
    return client.get<Policy[]>("/policies").then((r) => r.data);
  },

  createPolicy(payload: PolicyCreate): Promise<Policy> {
    return client.post<Policy>("/policies", payload).then((r) => r.data);
  },

  updatePolicy(policyId: string, payload: PolicyUpdate): Promise<Policy> {
    return client.patch<Policy>(`/policies/${policyId}`, payload).then((r) => r.data);
  },

  // ---- Dashboard analytics ------------------------------------------------
  dashboardOverview(): Promise<DashboardOverview> {
    return client.get<DashboardOverview>("/dashboard/overview").then((r) => r.data);
  },

  dashboardTopRisks(): Promise<TopRiskEmployee[]> {
    return client.get<TopRiskEmployee[]>("/dashboard/top-risks").then((r) => r.data);
  },

  dashboardRuleStats(): Promise<Record<string, number>> {
    return client.get<Record<string, number>>("/dashboard/rule-stats").then((r) => r.data);
  },

  dashboardTimeline(days = 7): Promise<TimelinePoint[]> {
    return client.get<TimelinePoint[]>(`/dashboard/timeline?days=${days}`).then((r) => r.data);
  },

  // ---- Notifications ------------------------------------------------------
  listNotificationChannels(): Promise<NotificationChannel[]> {
    return client.get<NotificationChannel[]>("/notifications/channels").then((r) => r.data);
  },

  createNotificationChannel(payload: NotificationChannelCreate): Promise<NotificationChannel> {
    return client.post<NotificationChannel>("/notifications/channels", payload).then((r) => r.data);
  },

  updateNotificationChannel(
    channelId: string,
    payload: Partial<NotificationChannelCreate> & { enabled?: boolean }
  ): Promise<NotificationChannel> {
    return client.patch<NotificationChannel>(`/notifications/channels/${channelId}`, payload).then((r) => r.data);
  },

  deleteNotificationChannel(channelId: string): Promise<void> {
    return client.delete(`/notifications/channels/${channelId}`).then(() => undefined);
  },

  testNotificationChannel(channelId: string, message?: string): Promise<NotificationLog> {
    return client
      .post<NotificationLog>(`/notifications/channels/${channelId}/test`, {
        message: message ?? "SentinelX test notification",
      })
      .then((r) => r.data);
  },

  listNotificationLogs(limit = 50): Promise<NotificationLog[]> {
    return client.get<NotificationLog[]>(`/notifications/logs?limit=${limit}`).then((r) => r.data);
  },

  // ---- SIEM integrations --------------------------------------------------
  listSiemIntegrations(): Promise<SiemIntegration[]> {
    return client.get<SiemIntegration[]>("/siem/integrations").then((r) => r.data);
  },

  createSiemIntegration(payload: SiemIntegrationCreate): Promise<SiemIntegration> {
    return client.post<SiemIntegration>("/siem/integrations", payload).then((r) => r.data);
  },

  updateSiemIntegration(
    integrationId: string,
    payload: Partial<SiemIntegrationCreate> & { enabled?: boolean }
  ): Promise<SiemIntegration> {
    return client.patch<SiemIntegration>(`/siem/integrations/${integrationId}`, payload).then((r) => r.data);
  },

  deleteSiemIntegration(integrationId: string): Promise<void> {
    return client.delete(`/siem/integrations/${integrationId}`).then(() => undefined);
  },

  testSiemIntegration(integrationId: string): Promise<{ ok: boolean; error?: string | null }> {
    return client.post(`/siem/integrations/${integrationId}/test`).then((r) => r.data);
  },

  // ---- Reports ------------------------------------------------------------
  reportSummary(days = 30): Promise<ReportSummary> {
    return client.get<ReportSummary>(`/reports/summary?days=${days}`).then((r) => r.data);
  },

  reportCsvUrl(days = 30): string {
    return `${BASE_URL}/reports/summary?format=csv&days=${days}`;
  },

  // ---- SSO ----------------------------------------------------------------
  ssoConfig(): Promise<SsoConfig> {
    return client.get<SsoConfig>("/auth/sso/config").then((r) => r.data);
  },

  ssoCallback(code: string, state: string): Promise<TokenResponse> {
    return client.post<TokenResponse>("/auth/sso/callback", { code, state }).then((r) => r.data);
  },
};

export { toApiError };
