import { useQuery } from "@tanstack/react-query";
import { getReadiness } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Live backend connectivity indicator.
 *
 * This reflects the real readiness endpoint. An analyst must be able to tell
 * "nothing is happening" from "the console lost the control plane" — showing a
 * healthy state while disconnected would be worse than showing nothing.
 */
export function BackendStatus() {
  const { data, isError, isPending } = useQuery({
    queryKey: ["readiness"],
    queryFn: getReadiness,
    refetchInterval: 10_000,
    retry: false,
  });

  const state = isPending
    ? { label: "Connecting…", tone: "bg-muted-foreground" }
    : isError
      ? { label: "Backend unreachable", tone: "bg-sev-critical" }
      : data?.status === "ok"
        ? { label: "Control plane online", tone: "bg-sev-low" }
        : { label: "Degraded", tone: "bg-sev-medium" };

  return (
    <div className="flex items-center gap-2 px-2 py-1 text-xs text-muted-foreground">
      <span className={cn("size-2 shrink-0 rounded-full", state.tone)} aria-hidden />
      <span className="truncate">{state.label}</span>
    </div>
  );
}
