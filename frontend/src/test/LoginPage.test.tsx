import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithRouter, mockTokenResponse, mockUser } from "./utils";
import { LoginPage } from "../pages/LoginPage";
import { AuthProvider } from "../auth/AuthContext";
import * as client from "../api/client";

function renderLogin() {
  return renderWithRouter(
    <AuthProvider>
      <LoginPage />
    </AuthProvider>,
    { route: "/login" }
  );
}

describe("LoginPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the sign-in form", () => {
    renderLogin();
    expect(screen.getByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/work email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("shows an error message when login fails", async () => {
    vi.spyOn(client.api, "login").mockRejectedValue({
      message: "Incorrect email or password.",
      status: 401,
    });
    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByLabelText(/work email/i), "admin@acme.corp");
    await user.type(screen.getByLabelText(/password/i), "wrongpass");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() =>
      expect(screen.getByText(/incorrect email or password/i)).toBeInTheDocument()
    );
  });

  it("calls the login API with the entered credentials", async () => {
    const loginSpy = vi
      .spyOn(client.api, "login")
      .mockResolvedValue(mockTokenResponse);
    vi.spyOn(client.api, "me").mockResolvedValue(mockUser);

    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByLabelText(/work email/i), "admin@acme.corp");
    await user.type(screen.getByLabelText(/password/i), "SuperSecret123!");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() =>
      expect(loginSpy).toHaveBeenCalledWith({
        email: "admin@acme.corp",
        password: "SuperSecret123!",
      })
    );
  });
});
