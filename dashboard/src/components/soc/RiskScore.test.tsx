import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FactorBreakdown, RiskScore } from "./RiskScore";

describe("RiskScore", () => {
  it("says a session is not scored rather than showing zero", () => {
    // Zero risk and no assessment are entirely different states.
    render(<RiskScore score={undefined} />);
    expect(screen.getByText(/not scored/i)).toBeInTheDocument();
  });

  it("shows the score alongside its band", () => {
    render(<RiskScore score={87} level="CRITICAL" />);
    expect(screen.getByText("87")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });
});

describe("FactorBreakdown", () => {
  const factors = [
    { code: "NEW_DEVICE", label: "New device for this user", contribution: 20 },
    { code: "UNUSUAL_LOGIN_TIME", label: "Unusual sign-in time", contribution: 15 },
  ];

  it("lists every contribution and totals them", () => {
    render(<FactorBreakdown factors={factors} total={35} />);

    expect(screen.getByText("+20")).toBeInTheDocument();
    expect(screen.getByText("+15")).toBeInTheDocument();
    expect(screen.getByText("35")).toBeInTheDocument();
  });

  it("flags a total that does not reconcile with the stored score", () => {
    // The backend guarantees these agree. If they ever disagree, hiding it
    // would be worse than showing it.
    render(<FactorBreakdown factors={factors} total={99} />);
    expect(screen.getByText(/does not reconcile/i)).toBeInTheDocument();
  });

  it("explains an empty breakdown rather than showing nothing", () => {
    render(<FactorBreakdown factors={[]} total={0} />);
    expect(screen.getByText(/normal behaviour/i)).toBeInTheDocument();
  });
});
