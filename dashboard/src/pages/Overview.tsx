import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { Stat } from "@/components/soc/Stat";
import { formatTime, severityVariant } from "@/lib/risk";

/**
 * Overview.
 *
 * Every figure is counted from stored data. Nothing on this page is estimated,
 * and a counter with nothing to count shows zero rather than being hidden.
 */
export function Overview() {
  const { data, isPending, error } = useQuery({
    queryKey: ["overview"],
    queryFn: api.overview,
    refetchInterval: 5_000,
    retry: false,
  });

  return (
    <>
      <PageHeader
        title="Overview"
        description="Fleet state, live sessions and recent security activity."
      />

      <div className="space-y-6 p-8">
        <Async isPending={isPending} error={error} data={data}>
          {(overview) => (
            <>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <Stat label="Endpoints" value={overview.endpoints} />
                <Stat
                  label="Trusted"
                  value={overview.endpoints_trusted}
                  tone="ok"
                  hint="device trust at or above 70"
                />
                <Stat
                  label="At risk"
                  value={overview.endpoints_at_risk}
                  tone={overview.endpoints_at_risk > 0 ? "warn" : undefined}
                  hint="below 70, or posture never reported"
                />
                <Stat
                  label="Open incidents"
                  value={overview.open_incidents}
                  tone={overview.critical_incidents > 0 ? "bad" : undefined}
                  hint={`${overview.critical_incidents} critical`}
                />
              </div>

              <div className="grid gap-4 lg:grid-cols-3">
                <Card>
                  <CardHeader>
                    <CardTitle>Sessions</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex items-baseline justify-between">
                      <span className="text-sm text-muted-foreground">Active</span>
                      <span className="tabular text-2xl font-semibold">
                        {overview.active_sessions}
                      </span>
                    </div>
                    <div className="flex items-baseline justify-between">
                      <span className="text-sm text-muted-foreground">High or critical risk</span>
                      <span
                        className={
                          overview.high_risk_sessions > 0
                            ? "tabular text-2xl font-semibold text-sev-critical"
                            : "tabular text-2xl font-semibold"
                        }
                      >
                        {overview.high_risk_sessions}
                      </span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="lg:col-span-2">
                  <CardHeader>
                    <CardTitle>Risk distribution</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <RiskDistribution distribution={overview.risk_distribution} />
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>Recent security events</CardTitle>
                </CardHeader>
                <CardContent className="px-0 pb-0">
                  {overview.recent_events.length === 0 ? (
                    <p className="px-5 pb-5 text-sm text-muted-foreground">
                      No events have been received yet.
                    </p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Time</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Endpoint</TableHead>
                          <TableHead>User</TableHead>
                          <TableHead>Detail</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {overview.recent_events.map((event) => (
                          <TableRow key={event.id}>
                            <TableCell className="tabular whitespace-nowrap text-muted-foreground">
                              {formatTime(event.occurred_at)}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{event.event_type}</TableCell>
                            <TableCell>
                              <Badge variant={severityVariant(event.severity)}>
                                {event.severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="truncate">{event.device_hostname || "—"}</TableCell>
                            <TableCell className="truncate">{event.user_name || "—"}</TableCell>
                            <TableCell className="max-w-xs truncate text-xs text-muted-foreground">
                              {describeMetadata(event.metadata)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </Async>
      </div>
    </>
  );
}

/** A horizontal bar of active sessions by band. */
function RiskDistribution({ distribution }: { distribution: Record<string, number> }) {
  const order = ["LOW", "MEDIUM", "ELEVATED", "HIGH", "CRITICAL", "UNSCORED"] as const;
  const total = Object.values(distribution).reduce((a, b) => a + b, 0);

  if (total === 0) {
    return <p className="text-sm text-muted-foreground">No active sessions to distribute.</p>;
  }

  const colour: Record<string, string> = {
    LOW: "bg-sev-low",
    MEDIUM: "bg-sev-medium",
    ELEVATED: "bg-sev-elevated",
    HIGH: "bg-sev-high",
    CRITICAL: "bg-sev-critical",
    UNSCORED: "bg-muted-foreground",
  };

  return (
    <div className="space-y-3">
      <div className="flex h-3 w-full overflow-hidden rounded-full">
        {order.map((band) => {
          const count = distribution[band] ?? 0;
          if (count === 0) return null;
          return (
            <div
              key={band}
              className={colour[band]}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${band}: ${count}`}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-1.5 text-xs">
        {order.map((band) => {
          const count = distribution[band] ?? 0;
          if (count === 0) return null;
          return (
            <span key={band} className="flex items-center gap-1.5">
              <span className={`size-2 rounded-full ${colour[band]}`} />
              <span className="text-muted-foreground">{band}</span>
              <span className="tabular font-medium">{count}</span>
            </span>
          );
        })}
      </div>
    </div>
  );
}

function describeMetadata(metadata: Record<string, string> | undefined): string {
  if (!metadata) return "";
  return Object.entries(metadata)
    .filter(([key]) => !key.startsWith("netra."))
    .map(([key, value]) => `${key}=${value}`)
    .join("  ");
}
