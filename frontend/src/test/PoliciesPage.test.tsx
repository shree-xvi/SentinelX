import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithRouter } from "./utils";
import { PoliciesPage } from "../pages/PoliciesPage";
import { AuthProvider } from "../auth/AuthContext";
import * as client from "../api/client";
import type { Policy } from "../api/types";

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    id: "pol-1",
    tenant_id: "tenant-1",
    name: "Brute Force Detection",
    rule_type: "BRUTE_FORCE",
    description: "Detects rapid successive authentication failures.",
    severity: "HIGH",
    enabled: true,
    conditions: { threshold: 5, window_minutes: 5 },
    created_at: "2026-10-14T10:00:00Z",
    ...overrides,
  };
}

function renderPolicies(role: string) {
  window.localStorage.setItem("sentinelx_access_token", "tok");
  const spy = vi.spyOn(client.api, "me").mockResolvedValue({
    id: "user-1",
    tenant_id: "tenant-1",
    email: "admin@acme.corp",
    full_name: "Alice",
    role,
    is_active: true,
  });
  return { spy, utils: renderWithRouter(<AuthProvider><PoliciesPage /></AuthProvider>, { route: "/policies" }) };
}

describe("PoliciesPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists detection policies", async () => {
    vi.spyOn(client.api, "listPolicies").mockResolvedValue([makePolicy()]);
    renderPolicies("admin");

    await waitFor(() =>
      expect(screen.getByText("Brute Force Detection")).toBeInTheDocument()
    );
    expect(screen.getByText("BRUTE_FORCE")).toBeInTheDocument();
  });

  it("toggles a policy via the switch when the user is an admin", async () => {
    vi.spyOn(client.api, "listPolicies").mockResolvedValue([makePolicy({ enabled: true })]);
    const toggleSpy = vi
      .spyOn(client.api, "updatePolicy")
      .mockResolvedValue(makePolicy({ enabled: false }));

    const user = userEvent.setup();
    renderPolicies("admin");

    const toggle = await screen.findByRole("switch", { name: /toggle brute_force/i });
    expect(toggle).toHaveAttribute("aria-checked", "true");
    await user.click(toggle);

    await waitFor(() =>
      expect(toggleSpy).toHaveBeenCalledWith("pol-1", { enabled: false })
    );
  });

  it("disables the toggle for non-admin users", async () => {
    vi.spyOn(client.api, "listPolicies").mockResolvedValue([makePolicy()]);
    renderPolicies("analyst");

    const toggle = await screen.findByRole("switch", { name: /toggle brute_force/i });
    expect(toggle).toBeDisabled();
  });
});
