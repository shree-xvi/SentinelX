import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithRouter } from "./utils";
import { ReportsPage } from "../pages/ReportsPage";
import { AuthProvider } from "../auth/AuthContext";
import * as client from "../api/client";
import type { ReportSummary } from "../api/types";

function makeSummary(): ReportSummary {
  return {
    tenant: { id: "tenant-1", name: "Acme", domain: "acme.corp" },
    period_days: 30,
    generated_at: "2026-10-14T10:00:00Z",
    alerts: {
      total: 3,
      by_severity: { HIGH: 2, CRITICAL: 1 },
      by_type: { DATA_EXFILTRATION: 3 },
      rows: [],
    },
    cases: { total: 1, open: 1, rows: [] },
    employees: { total: 10, high_risk: 2, rows: [] },
  };
}

describe("ReportsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the summary report", async () => {
    window.localStorage.setItem("sentinelx_access_token", "tok");
    vi.spyOn(client.api, "me").mockResolvedValue({
      id: "user-1",
      tenant_id: "tenant-1",
      email: "admin@acme.corp",
      full_name: "Alice",
      role: "admin",
      is_active: true,
    });
    vi.spyOn(client.api, "reportSummary").mockResolvedValue(makeSummary());
    renderWithRouter(
      <AuthProvider>
        <ReportsPage />
      </AuthProvider>,
      { route: "/reports" }
    );
    await waitFor(() => expect(screen.getByText("Alerts by severity")).toBeInTheDocument());
    expect(screen.getByText("DATA_EXFILTRATION")).toBeInTheDocument();
  });
});
