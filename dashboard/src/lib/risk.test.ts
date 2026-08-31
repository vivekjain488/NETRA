import { describe, expect, it } from "vitest";
import { DEFAULT_THRESHOLDS, riskLevel, riskVariant } from "./risk";

describe("riskLevel", () => {
  it("maps the spec §19 bands", () => {
    const cases: Array<[number, string]> = [
      [0, "LOW"],
      [30, "LOW"],
      [31, "MEDIUM"],
      [50, "MEDIUM"],
      [51, "ELEVATED"],
      [70, "ELEVATED"],
      [71, "HIGH"],
      [85, "HIGH"],
      [86, "CRITICAL"],
      [100, "CRITICAL"],
    ];
    for (const [score, expected] of cases) {
      expect(riskLevel(score), `score ${score}`).toBe(expected);
    }
  });

  it("clamps out-of-range scores instead of throwing", () => {
    // A malformed score must not blank the SOC console mid-incident.
    expect(riskLevel(-10)).toBe("LOW");
    expect(riskLevel(9001)).toBe("CRITICAL");
  });

  it("honours reconfigured thresholds", () => {
    const strict = { low: 10, medium: 20, elevated: 40, high: 60 };
    expect(riskLevel(25, strict)).toBe("ELEVATED");
    expect(riskLevel(25, DEFAULT_THRESHOLDS)).toBe("LOW");
  });

  it("rounds fractional scores", () => {
    expect(riskLevel(30.4)).toBe("LOW");
    expect(riskLevel(30.6)).toBe("MEDIUM");
  });
});

describe("riskVariant", () => {
  it("produces the badge variant for each level", () => {
    expect(riskVariant("CRITICAL")).toBe("critical");
    expect(riskVariant("LOW")).toBe("low");
  });
});
