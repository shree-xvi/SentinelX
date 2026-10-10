import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithRouter } from "./utils";
import { AlertsPage } from "../pages/AlertsPage";
import * as client from "../api/client";
import type { Alert } from "../api/types";

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "alert-1",
    tenant_id: "tenant-1",
    employee_id: "emp-1",
    alert_type: "BRUTE_FORCE",
    severity: "HIGH",
    risk_score: 72.5,
    risk_level: "HIGH",
    source_ip: "198.51.100.42",
    fingerprint: "abc123def456",
    status: "New",
    evidence: { rule: "BRUTE_FORCE", attempts: 5 },
    detected_at: "2026-10-14T10:00:00Z",
    created_at: "2026-10-14T10:00:00Z",
    ...overrides,
  };
}

describe("AlertsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists alerts and shows details when one is selected", async () => {
    vi.spyOn(client.api, "listAlerts").mockResolvedValue([makeAlert()]);
    const user = userEvent.setup();
    renderWithRouter(<AlertsPage />, { route: "/alerts" });

    await waitFor(() =>
      expect(screen.getByText("Brute Force")).toBeInTheDocument()
    );

    // Select the alert row to reveal the detail panel
    await user.click(screen.getByText("Brute Force"));
    expect(screen.getByText("198.51.100.42")).toBeInTheDocument();
  });

  it("shows an empty state when there are no alerts", async () => {
    vi.spyOn(client.api, "listAlerts").mockResolvedValue([]);
    renderWithRouter(<AlertsPage />, { route: "/alerts" });
    await waitFor(() =>
      expect(screen.getByText(/no alerts match/i)).toBeInTheDocument()
    );
  });

  it("updates alert status and reflects the new status", async () => {
    const alert = makeAlert();
    const listSpy = vi.spyOn(client.api, "listAlerts").mockResolvedValue([alert]);
    const updateSpy = vi
      .spyOn(client.api, "updateAlertStatus")
      .mockResolvedValue(makeAlert({ status: "Investigating" }));

    const user = userEvent.setup();
    renderWithRouter(<AlertsPage />, { route: "/alerts" });

    await waitFor(() => screen.getByText("Brute Force"));
    await user.click(screen.getByText("Brute Force"));

    // Click the "Investigating" status button in the detail panel
    const detail = screen.getByRole("button", { name: /escalate to case/i }).closest(".card")!;
    const investigatingBtn = within(detail as HTMLElement).getByRole("button", {
      name: "Investigating",
    });
    await user.click(investigatingBtn);

    await waitFor(() =>
      expect(updateSpy).toHaveBeenCalledWith("alert-1", "Investigating")
    );
    expect(listSpy).toHaveBeenCalled();
  });
});
