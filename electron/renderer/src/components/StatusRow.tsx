import type { Available } from "@shared/contract";

/**
 * One labelled status line.
 *
 * An unavailable value renders as muted explanatory text rather than a dash or
 * a zero, so the user is never shown a number the system does not have.
 */
export function StatusRow({
  label,
  value,
  tone,
}: {
  label: string;
  value: Available<string | number> | string;
  tone?: "ok" | "warn" | "bad";
}) {
  const toneClass =
    tone === "ok"
      ? "text-ok"
      : tone === "warn"
        ? "text-warn"
        : tone === "bad"
          ? "text-bad"
          : "";

  const rendered =
    typeof value === "string" ? (
      <span className={toneClass}>{value}</span>
    ) : value.available ? (
      <span className={toneClass}>{value.value}</span>
    ) : (
      <span className="text-xs text-muted-foreground italic">{value.reason}</span>
    );

  return (
    <div className="flex items-baseline justify-between gap-6 py-2.5">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-right text-sm font-medium">{rendered}</dd>
    </div>
  );
}
