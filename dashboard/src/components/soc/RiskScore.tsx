import { Badge } from "@/components/ui/badge";
import { riskVariant, type RiskLevel } from "@/lib/risk";
import { cn } from "@/lib/utils";

/**
 * A risk score with its band.
 *
 * The number and the colour say the same thing, so the page is readable at a
 * glance and still readable without colour.
 */
export function RiskScore({
  score,
  level,
  size = "default",
}: {
  score: number | undefined;
  level?: string;
  size?: "default" | "large";
}) {
  if (score === undefined || score === null) {
    return <span className="text-sm text-muted-foreground">not scored</span>;
  }

  const band = (level?.toUpperCase() ?? "LOW") as RiskLevel;
  return (
    <span className="inline-flex items-center gap-2">
      <span
        className={cn(
          "tabular font-semibold",
          size === "large" ? "text-3xl" : "text-sm",
        )}
      >
        {score}
      </span>
      <Badge variant={riskVariant(band)}>{band}</Badge>
    </span>
  );
}

/**
 * The factor breakdown behind a score.
 *
 * Contributions are shown individually and totalled, because a score without
 * its reasons is not actionable — and because the total proves the explanation
 * reconciles with the number (spec §20).
 */
export function FactorBreakdown({
  factors,
  total,
}: {
  factors: Array<{ code: string; label: string; contribution: number; detail?: string }>;
  total: number;
}) {
  const sum = factors.reduce((acc, factor) => acc + factor.contribution, 0);

  return (
    <div className="text-sm">
      <ul className="divide-y">
        {factors.map((factor) => (
          <li key={factor.code} className="flex items-baseline gap-3 py-2">
            <span className="tabular w-10 shrink-0 text-right font-medium text-sev-high">
              +{factor.contribution}
            </span>
            <span className="min-w-0 flex-1">
              <span className="font-medium">{factor.label}</span>
              {factor.detail && (
                <span className="block text-xs text-muted-foreground">{factor.detail}</span>
              )}
            </span>
          </li>
        ))}
        {factors.length === 0 && (
          <li className="py-2 text-muted-foreground">
            No risk factors — this session matches the user&apos;s normal behaviour.
          </li>
        )}
      </ul>

      <div className="mt-1 flex items-baseline gap-3 border-t-2 border-foreground/70 pt-2">
        <span className="tabular w-10 shrink-0 text-right font-semibold">{sum}</span>
        <span className="font-medium">Total</span>
        {sum !== total && (
          // Should never happen: the backend guarantees factors sum to the
          // score. Showing the discrepancy is better than hiding it.
          <span className="text-xs text-sev-critical">
            does not reconcile with the stored score of {total}
          </span>
        )}
      </div>
    </div>
  );
}
