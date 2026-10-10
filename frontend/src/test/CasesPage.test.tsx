import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithRouter } from "./utils";
import { CasesPage } from "../pages/CasesPage";
import * as client from "../api/client";
import type { Case } from "../api/types";

function makeCase(overrides: Partial<Case> = {}): Case {
  return {
    id: "case-1",
    tenant_id: "tenant-1",
    alert_id: null,
    assigned_to: "user-1",
    title: "Investigate off-hours access",
    description: "User active at 03:00",
    status: "New",
    priority: "HIGH",
    created_at: "2026-10-14T10:00:00Z",
    updated_at: "2026-10-14T10:00:00Z",
    resolved_at: null,
    notes: [],
    ...overrides,
  };
}

describe("CasesPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists cases and shows the empty detail prompt", async () => {
    vi.spyOn(client.api, "listCases").mockResolvedValue([makeCase()]);
    renderWithRouter(<CasesPage />, { route: "/cases" });

    await waitFor(() =>
      expect(screen.getByText("Investigate off-hours access")).toBeInTheDocument()
    );
    expect(screen.getByText(/select a case/i)).toBeInTheDocument();
  });

  it("shows an empty state when there are no cases", async () => {
    vi.spyOn(client.api, "listCases").mockResolvedValue([]);
    renderWithRouter(<CasesPage />, { route: "/cases" });
    await waitFor(() =>
      expect(screen.getByText(/no investigation cases/i)).toBeInTheDocument()
    );
  });

  it("adds a note to the selected case", async () => {
    const caseWithNotes = makeCase({
      notes: [
        {
          id: "n1",
          case_id: "case-1",
          author_id: "user-1",
          note: "Initial finding",
          action_type: "comment",
          created_at: "2026-10-14T10:00:00Z",
        },
      ],
    });
    vi.spyOn(client.api, "listCases").mockResolvedValue([caseWithNotes]);
    vi.spyOn(client.api, "getCase").mockResolvedValue(caseWithNotes);
    const noteSpy = vi
      .spyOn(client.api, "addCaseNote")
      .mockResolvedValue({
        id: "n2",
        case_id: "case-1",
        author_id: "user-1",
        note: "Follow up",
        action_type: "comment",
        created_at: "2026-10-14T11:00:00Z",
      });

    const user = userEvent.setup();
    renderWithRouter(<CasesPage />, { route: "/cases" });

    await waitFor(() => screen.getByText("Investigate off-hours access"));
    await user.click(screen.getByText("Investigate off-hours access"));

    const noteBox = await screen.findByLabelText(/add a note/i);
    // Set the value in a single event to avoid a re-render race with the
    // async case reload triggered by selecting the row.
    fireEvent.change(noteBox, { target: { value: "Follow up" } });
    await user.click(screen.getByRole("button", { name: /add note/i }));

    await waitFor(() =>
      expect(noteSpy).toHaveBeenCalledWith("case-1", "Follow up")
    );
  });
});
