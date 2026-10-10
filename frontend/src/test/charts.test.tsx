import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { BarChart, DonutChart, TimelineChart } from "../components/charts";

describe("BarChart", () => {
  it("renders a labeled row per data point", () => {
    render(
      <BarChart
        data={[
          { label: "Brute Force", value: 10 },
          { label: "Data Exfiltration", value: 4 },
        ]}
      />
    );
    expect(screen.getByText("Brute Force")).toBeInTheDocument();
    expect(screen.getByText("Data Exfiltration")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
  });

  it("shows an empty message with no data", () => {
    render(<BarChart data={[]} />);
    expect(screen.getByText(/no data available/i)).toBeInTheDocument();
  });
});

describe("DonutChart", () => {
  it("renders a legend for non-zero severities", () => {
    render(
      <DonutChart data={{ CRITICAL: 3, HIGH: 5, MEDIUM: 0, LOW: 2 }} />
    );
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    // MEDIUM has a zero count and should be omitted from the legend.
    const legend = screen.getByRole("img", { name: /severity distribution/i });
    expect(legend.textContent).not.toContain("MEDIUM");
  });

  it("shows an empty message with no data", () => {
    render(<DonutChart data={{ CRITICAL: 0 }} />);
    expect(screen.getByText(/no alerts to summarize/i)).toBeInTheDocument();
  });
});

describe("TimelineChart", () => {
  it("renders a column per timeline point", () => {
    render(
      <TimelineChart
        data={[
          { date: "2026-10-12", total: 3, by_severity: { HIGH: 3 } },
          { date: "2026-10-13", total: 1, by_severity: { LOW: 1 } },
        ]}
      />
    );
    expect(screen.getByRole("img", { name: /alert timeline/i })).toBeInTheDocument();
  });

  it("shows an empty message with no points", () => {
    render(<TimelineChart data={[]} />);
    expect(screen.getByText(/no alerts in this period/i)).toBeInTheDocument();
  });
});
