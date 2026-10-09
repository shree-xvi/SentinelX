import { describe, expect, it } from "vitest";
import { formatDateShort, formatDateTime, humanizeRuleType, timeAgo } from "../utils/format";

describe("formatDateTime", () => {
  it("returns an em dash for missing values", () => {
    expect(formatDateTime(null)).toBe("—");
    expect(formatDateTime(undefined)).toBe("—");
  });

  it("returns an em dash for invalid dates", () => {
    expect(formatDateTime("not-a-date")).toBe("—");
  });

  it("formats a valid ISO timestamp", () => {
    const result = formatDateTime("2026-10-14T10:30:00Z");
    expect(result).not.toBe("—");
    expect(result).toMatch(/\d{4}/);
  });
});

describe("formatDateShort", () => {
  it("returns an empty string for missing values", () => {
    expect(formatDateShort(null)).toBe("");
  });
});

describe("timeAgo", () => {
  it("reports 'never' for missing timestamps", () => {
    expect(timeAgo(null)).toBe("never");
  });

  it("reports seconds for very recent timestamps", () => {
    const tenSecondsAgo = new Date(Date.now() - 10_000).toISOString();
    expect(timeAgo(tenSecondsAgo)).toMatch(/s ago$/);
  });

  it("reports minutes within the hour", () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
    expect(timeAgo(fiveMinAgo)).toMatch(/m ago$/);
  });
});

describe("humanizeRuleType", () => {
  it("converts snake case rule types to title case", () => {
    expect(humanizeRuleType("BRUTE_FORCE")).toBe("Brute Force");
    expect(humanizeRuleType("SUSPICIOUS_LOGIN_AFTER_FAILURES")).toBe(
      "Suspicious Login After Failures"
    );
    expect(humanizeRuleType("DATA_EXFILTRATION")).toBe("Data Exfiltration");
  });
});
