import { cn } from "@/lib/utils";

/**
 * One counted figure on the overview.
 *
 * A zero is shown as zero rather than hidden: an operations page must never
 * let a missing number read as a healthy one.
 */
export function Stat({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: number | string;
  tone?: "ok" | "warn" | "bad";
  hint?: string;
}) {
  return (
    <div className="rounded-lg border bg-card px-5 py-4">
      <div
        className={cn(
          "tabular text-3xl font-semibold tracking-tight",
          tone === "ok" && "text-sev-low",
          tone === "warn" && "text-sev-elevated",
          tone === "bad" && "text-sev-critical",
        )}
      >
        {value}
      </div>
      <div className="mt-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {label}
      </div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}
