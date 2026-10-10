import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithRouter } from "./utils";
import { IntegrationsPage } from "../pages/IntegrationsPage";
import { AuthProvider } from "../auth/AuthContext";
import * as client from "../api/client";
import type { NotificationChannel, NotificationLog, SiemIntegration } from "../api/types";

function makeChannel(overrides: Partial<NotificationChannel> = {}): NotificationChannel {
  return {
    id: "chan-1",
    tenant_id: "tenant-1",
    name: "SecOps webhook",
    channel_type: "webhook",
    target: "https://hooks.example.com/sentinelx",
    min_severity: "HIGH",
    enabled: true,
    created_at: "2026-10-14T10:00:00Z",
    ...overrides,
  };
}

function makeIntegration(overrides: Partial<SiemIntegration> = {}): SiemIntegration {
  return {
    id: "siem-1",
    tenant_id: "tenant-1",
    name: "Splunk",
    provider: "splunk_hec",
    endpoint: "https://splunk.example.com/services/collector",
    format: "json",
    forward_scope: "alerts",
    min_severity: "MEDIUM",
    enabled: true,
    last_status: "ok",
    last_error: null,
    last_sent_at: null,
    created_at: "2026-10-14T10:00:00Z",
    ...overrides,
  };
}

function makeLog(overrides: Partial<NotificationLog> = {}): NotificationLog {
  return {
    id: "log-1",
    channel_id: "chan-1",
    alert_id: null,
    status: "sent",
    response_status: 200,
    error: null,
    created_at: "2026-10-14T10:00:00Z",
    ...overrides,
  };
}

function renderIntegrations(role = "admin") {
  window.localStorage.setItem("sentinelx_access_token", "tok");
  vi.spyOn(client.api, "me").mockResolvedValue({
    id: "user-1",
    tenant_id: "tenant-1",
    email: "admin@acme.corp",
    full_name: "Alice",
    role,
    is_active: true,
  });
  vi.spyOn(client.api, "listNotificationChannels").mockResolvedValue([makeChannel()]);
  vi.spyOn(client.api, "listSiemIntegrations").mockResolvedValue([makeIntegration()]);
  vi.spyOn(client.api, "listNotificationLogs").mockResolvedValue([makeLog()]);
  return renderWithRouter(
    <AuthProvider>
      <IntegrationsPage />
    </AuthProvider>,
    { route: "/integrations" }
  );
}

describe("IntegrationsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists channels, SIEM integrations, and delivery logs", async () => {
    renderIntegrations();
    await waitFor(() => expect(screen.getByText("SecOps webhook")).toBeInTheDocument());
    expect(screen.getByText("Splunk")).toBeInTheDocument();
    expect(screen.getByText("sent")).toBeInTheDocument();
  });

  it("sends a test notification for a channel", async () => {
    const user = userEvent.setup();
    renderIntegrations();
    const testSpy = vi.spyOn(client.api, "testNotificationChannel").mockResolvedValue(makeLog());
    await screen.findByText("SecOps webhook");
    const sendButtons = screen.getAllByRole("button", { name: /send test/i });
    await user.click(sendButtons[0]);
    await waitFor(() => expect(testSpy).toHaveBeenCalledWith("chan-1"));
  });
});
