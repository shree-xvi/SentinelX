import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithRouter } from "./utils";
import { DashboardPage } from "../pages/DashboardPage";
import * as client from "../api/client";
import type { TimelinePoint } from "../api/types";

const overview = {
  total_alerts: 42,
  average_risk_score: 55.3,
  severities: { CRITICAL: 4, HIGH: 12, MEDIUM: 20, LOW: 6 },
  risk_levels: { CRITICAL: 4, HIGH: 12, MEDIUM: 20, LOW: 6 },
  cases: { open: 7, resolved: 15 },
};

const topRisks = [
  {
    id: "emp-1",
    employee_id: "EMP-1",
    name: "Bob Vance",
    department: "Sales",
    risk_score: 91.2,
    risk_level: "CRITICAL" as const,
    last_activity: new Date().toISOString(),
  },
];

const ruleStats = { BRUTE_FORCE: 10, DATA_EXFILTRATION: 5 };

const timeline: TimelinePoint[] = [
  { date: "2026-10-12", total: 3, by_severity: { HIGH: 2, LOW: 1 } },
  { date: "2026-10-13", total: 5, by_severity: { CRITICAL: 1, MEDIUM: 4 } },
];

describe("DashboardPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(client.api, "dashboardOverview").mockResolvedValue(overview);
    vi.spyOn(client.api, "dashboardTopRisks").mockResolvedValue(topRisks);
    vi.spyOn(client.api, "dashboardRuleStats").mockResolvedValue(ruleStats);
    vi.spyOn(client.api, "dashboardTimeline").mockResolvedValue(timeline);
  });

  it("renders the key overview metrics", async () => {
    const { container } = renderWithRouter(<DashboardPage />, { route: "/overview" });

    await waitFor(() =>
      expect(screen.getByText(/security overview/i)).toBeInTheDocument()
    );
    // The total alerts stat tile and the top risk employee should be visible.
    const statTiles = container.querySelectorAll(".stat .value");
    expect(statTiles[0]).toHaveTextContent("42");
    expect(screen.getByText("55.3")).toBeInTheDocument();
    expect(screen.getByText("Bob Vance")).toBeInTheDocument();
  });

  it("renders an error state when the overview fails", async () => {
    vi.spyOn(client.api, "dashboardOverview").mockRejectedValue({
      message: "Service unavailable",
      status: 503,
    });
    renderWithRouter(<DashboardPage />, { route: "/overview" });
    await waitFor(() =>
      expect(screen.getByText(/service unavailable/i)).toBeInTheDocument()
    );
  });
});
