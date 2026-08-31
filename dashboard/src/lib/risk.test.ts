import { describe, expect, it } from "vitest";
import {
  DEFAULT_THRESHOLDS,
  decisionVariant,
  riskLevel,
  riskVariant,
  severityVariant,
  timeAgo,
} from "./risk";

describe("riskLevel", () => {
  it("maps the spec §19 bands", () => {
    const cases: Array<[number, string]> = [
      [0, "LOW"], [30, "LOW"], [31, "MEDIUM"], [50, "MEDIUM"],
      [51, "ELEVATED"], [70, "ELEVATED"], [71, "HIGH"], [85, "HIGH"],
      [86, "CRITICAL"], [100, "CRITICAL"],
    ];
    for (const [score, expected] of cases) {
      expect(riskLevel(score), `score ${score}`).toBe(expected);
    }
  });

  it("clamps out-of-range scores instead of throwing", () => {
    // A malformed score must not blank the console mid-incident.
    expect(riskLevel(-10)).toBe("LOW");
    expect(riskLevel(9001)).toBe("CRITICAL");
  });

  it("honours reconfigured thresholds", () => {
    const strict = { low: 10, medium: 20, elevated: 40, high: 60 };
    expect(riskLevel(25, strict)).toBe("ELEVATED");
    expect(riskLevel(25, DEFAULT_THRESHOLDS)).toBe("LOW");
  });
});

describe("severityVariant", () => {
  it("keeps critical and high visually distinct", () => {
    expect(severityVariant("CRITICAL")).toBe("critical");
    expect(severityVariant("HIGH")).toBe("high");
    expect(severityVariant("INFO")).toBe("outline");
  });
});

describe("decisionVariant", () => {
  it("colours by how restrictive the outcome is", () => {
    // An operator should read severity from the shape of the page.
    expect(decisionVariant("ALLOW")).toBe("low");
    expect(decisionVariant("STEP_UP_MFA")).toBe("elevated");
    expect(decisionVariant("RESTRICT")).toBe("high");
    expect(decisionVariant("ISOLATE")).toBe("critical");
    expect(decisionVariant("DENY")).toBe("critical");
  });
});

describe("riskVariant", () => {
  it("produces the badge variant for each level", () => {
    expect(riskVariant("CRITICAL")).toBe("critical");
    expect(riskVariant("LOW")).toBe("low");
  });
});

describe("timeAgo", () => {
  it("reports never for an absent timestamp", () => {
    // A device that has never reported must not read as one that just did.
    expect(timeAgo(undefined)).toBe("never");
  });

  it("scales the unit to the age", () => {
    const ago = (seconds: number) => new Date(Date.now() - seconds * 1000).toISOString();
    expect(timeAgo(ago(30))).toMatch(/s ago$/);
    expect(timeAgo(ago(300))).toMatch(/m ago$/);
    expect(timeAgo(ago(7200))).toMatch(/h ago$/);
    expect(timeAgo(ago(200_000))).toMatch(/d ago$/);
  });
});
