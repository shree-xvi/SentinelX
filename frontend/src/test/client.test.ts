import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getStoredToken, setStoredToken, toApiError } from "../api/client";

beforeEach(() => {
  setStoredToken(null);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("token storage", () => {
  it("stores and retrieves a token", () => {
    setStoredToken("abc123");
    expect(getStoredToken()).toBe("abc123");
  });

  it("clears the token when set to null", () => {
    setStoredToken("abc123");
    setStoredToken(null);
    expect(getStoredToken()).toBeNull();
  });

  it("returns null when no token is present", () => {
    expect(getStoredToken()).toBeNull();
  });
});

describe("toApiError", () => {
  it("normalizes a string detail into a message", () => {
    const err = {
      isAxiosError: true,
      message: "Request failed",
      response: { status: 400, data: { detail: "Bad domain." } },
    };
    const result = toApiError(err);
    expect(result.message).toBe("Bad domain.");
    expect(result.status).toBe(400);
  });

  it("normalizes a validation array detail", () => {
    const err = {
      isAxiosError: true,
      message: "Unprocessable",
      response: { status: 422, data: { detail: [{ msg: "field required" }] } },
    };
    expect(toApiError(err).message).toBe("field required");
  });

  it("falls back to the axios message when there is no detail", () => {
    const err = { isAxiosError: true, message: "Network Error" };
    const result = toApiError(err);
    expect(result.message).toBe("Network Error");
    expect(result.status).toBe(0);
  });

  it("handles non-axios errors", () => {
    expect(toApiError(new Error("boom"))).toEqual({
      message: "Unexpected error.",
      status: 0,
    });
  });
});

