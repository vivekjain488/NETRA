import type { ReactNode } from "react";
import { ApiError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Renders the three states every console panel has.
 *
 * Failures name the request id so an analyst can find the matching backend log
 * line, rather than being told only that something went wrong.
 */
export function Async<T>({
  isPending,
  error,
  data,
  empty,
  children,
}: {
  isPending: boolean;
  error: unknown;
  data: T | undefined;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (isPending) {
    return <p className="px-1 py-6 text-sm text-muted-foreground">Loading…</p>;
  }

  if (error) {
    const detail =
      error instanceof ApiError
        ? `${error.problem?.detail ?? error.message}${
            error.requestId ? ` (request ${error.requestId})` : ""
          }`
        : error instanceof Error
          ? error.message
          : "The request failed.";

    return (
      <Card className="max-w-xl border-sev-critical/40">
        <CardHeader>
          <CardTitle className="text-sev-critical">Could not load this view</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">{detail}</CardContent>
      </Card>
    );
  }

  if (!data) {
    return <p className="px-1 py-6 text-sm text-muted-foreground">No data.</p>;
  }

  if (Array.isArray(data) && data.length === 0 && empty) {
    return <>{empty}</>;
  }

  return <>{children(data)}</>;
}
