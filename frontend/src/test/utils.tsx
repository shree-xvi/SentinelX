import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement, ReactNode } from "react";
import { setStoredToken } from "../api/client";
import type { TokenResponse, User } from "../api/types";

export const mockUser: User = {
  id: "user-1",
  tenant_id: "tenant-1",
  email: "admin@acme.corp",
  full_name: "Alice Admin",
  role: "admin",
  is_active: true,
};

export const mockTokenResponse: TokenResponse = {
  access_token: "test.jwt.token",
  token_type: "bearer",
  user_id: mockUser.id,
  tenant_id: mockUser.tenant_id,
  role: mockUser.role,
  email: mockUser.email,
};

/** Render a component wrapped in a MemoryRouter at an initial route. */
export function renderWithRouter(
  ui: ReactElement,
  { route = "/", ...options }: RenderOptions & { route?: string } = {}
) {
  return render(<MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>, options);
}

/** Convenience wrapper to seed an authenticated token before rendering. */
export function Wrapper({ children }: { children: ReactNode }) {
  setStoredToken(mockTokenResponse.access_token);
  return <MemoryRouter>{children}</MemoryRouter>;
}
