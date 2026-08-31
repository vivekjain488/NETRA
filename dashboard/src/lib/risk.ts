/**
 * Risk banding (spec §19).
 *
 * Thresholds are configuration, not constants: the backend owns the
 * authoritative values and the console renders whatever it is given. The
 * defaults here match the shipped configuration and exist only so the UI can
 * render before the first response arrives.
 */

export type RiskLevel = "LOW" | "MEDIUM" | "ELEVATED" | "HIGH" | "CRITICAL";

export interface RiskThresholds {
  low: number;
  medium: number;
  elevated: number;
  high: number;
}

export const DEFAULT_THRESHOLDS: RiskThresholds = {
  low: 30,
  medium: 50,
  elevated: 70,
  high: 85,
};

/** Maps a 0–100 score onto its risk band. Scores are clamped, not rejected. */
export function riskLevel(
  score: number,
  thresholds: RiskThresholds = DEFAULT_THRESHOLDS,
): RiskLevel {
  const clamped = Math.min(100, Math.max(0, Math.round(score)));
  if (clamped <= thresholds.low) return "LOW";
  if (clamped <= thresholds.medium) return "MEDIUM";
  if (clamped <= thresholds.elevated) return "ELEVATED";
  if (clamped <= thresholds.high) return "HIGH";
  return "CRITICAL";
}

/** Badge variant for a risk level. */
export function riskVariant(level: RiskLevel) {
  return level.toLowerCase() as Lowercase<RiskLevel>;
}
