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

/** Badge variant for an event or incident severity. */
export function severityVariant(severity: string) {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "critical" as const;
    case "HIGH":
      return "high" as const;
    case "MEDIUM":
    case "ELEVATED":
      return "elevated" as const;
    case "LOW":
      return "medium" as const;
    default:
      return "outline" as const;
  }
}

/**
 * Badge variant for a policy decision.
 *
 * Colour encodes how restrictive the outcome is, so an operator reads severity
 * from the shape of the page before reading any words.
 */
export function decisionVariant(decision: string) {
  switch (decision.toUpperCase()) {
    case "ALLOW":
      return "low" as const;
    case "ALLOW_MONITOR":
      return "outline" as const;
    case "VERIFY":
    case "STEP_UP_MFA":
      return "elevated" as const;
    case "RESTRICT":
      return "high" as const;
    case "ISOLATE":
    case "DENY":
      return "critical" as const;
    default:
      return "outline" as const;
  }
}

/** Formats a timestamp for an operations console: precise, not relative. */
export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/** Formats how long ago something happened, for freshness indicators. */
export function timeAgo(iso: string | undefined): string {
  if (!iso) return "never";
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return "unknown";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
