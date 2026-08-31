import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { FactorBreakdown, RiskScore } from "@/components/soc/RiskScore";
import { formatTime, riskVariant, timeAgo, type RiskLevel } from "@/lib/risk";

export function Sessions() {
  const [selected, setSelected] = useState<string | null>(null);

  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: api.sessions,
    refetchInterval: 5_000,
    retry: false,
  });

  return (
    <>
      <PageHeader
        title="Sessions"
        description="Live sessions under continuous evaluation, each bound to a verified user and device."
      />

      <div className="space-y-6 p-8">
        <Async isPending={sessions.isPending} error={sessions.error} data={sessions.data}>
          {({ sessions: list }) =>
            list.length === 0 ? (
              <Card className="max-w-xl">
                <CardHeader>
                  <CardTitle>No sessions yet</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  A session appears once a user signs in from an enrolled device and the device
                  attests the sign-in.
                </CardContent>
              </Card>
            ) : (
              <>
                <Card>
                  <CardContent className="px-0 py-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>User</TableHead>
                          <TableHead>Device</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Risk</TableHead>
                          <TableHead>Attestation</TableHead>
                          <TableHead>Started</TableHead>
                          <TableHead>Last seen</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {list.map((session) => (
                          <TableRow
                            key={session.id}
                            onClick={() => setSelected(session.id === selected ? null : session.id)}
                            className="cursor-pointer"
                          >
                            <TableCell className="font-medium">
                              {session.user_display_name || session.user_email || "—"}
                            </TableCell>
                            <TableCell>{session.device_hostname || "—"}</TableCell>
                            <TableCell>
                              <Badge variant={statusVariant(session.status)}>{session.status}</Badge>
                            </TableCell>
                            <TableCell>
                              <RiskScore score={session.current_risk} level={session.risk_level} />
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {session.attestation}
                            </TableCell>
                            <TableCell className="tabular whitespace-nowrap text-muted-foreground">
                              {formatTime(session.started_at)}
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              {timeAgo(session.last_seen_at)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {selected && <RiskPanel sessionId={selected} />}
              </>
            )
          }
        </Async>
      </div>
    </>
  );
}

function statusVariant(status: string) {
  switch (status) {
    case "ACTIVE":
      return "low" as const;
    case "RESTRICTED":
      return "high" as const;
    case "ISOLATED":
      return "critical" as const;
    default:
      return "outline" as const;
  }
}

/** Why a session scores what it scores, and how it got there. */
function RiskPanel({ sessionId }: { sessionId: string }) {
  const client = useQueryClient();

  const { data, isPending, error } = useQuery({
    queryKey: ["risk", sessionId],
    queryFn: () => api.risk(sessionId),
    refetchInterval: 5_000,
    retry: false,
  });

  const reevaluate = useMutation({
    mutationFn: () => api.evaluate(sessionId),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["risk", sessionId] });
      void client.invalidateQueries({ queryKey: ["sessions"] });
      void client.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-4">
          <CardTitle>Risk breakdown</CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={() => reevaluate.mutate()}
            disabled={reevaluate.isPending}
          >
            {reevaluate.isPending ? "Evaluating…" : "Re-evaluate now"}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <Async isPending={isPending} error={error} data={data}>
          {(risk) => (
            <div className="grid gap-8 lg:grid-cols-2">
              <div className="space-y-4">
                <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
                  <RiskScore score={risk.current.score} level={risk.current.level} size="large" />
                  <Badge variant="outline">{risk.current.recommended_action}</Badge>
                </div>
                <p className="font-mono text-xs text-muted-foreground">
                  {risk.current.model_version} · {formatTime(risk.current.computed_at)}
                  {risk.current.trigger_event && ` · triggered by ${risk.current.trigger_event}`}
                </p>
                <FactorBreakdown factors={risk.current.factors} total={risk.current.score} />
              </div>

              <div>
                <h3 className="mb-3 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                  Risk over the life of this session
                </h3>
                <RiskTrend history={risk.history} />
              </div>
            </div>
          )}
        </Async>
      </CardContent>
    </Card>
  );
}

/**
 * The session's risk trajectory.
 *
 * Each step names what triggered it, so the question is not "when did risk
 * rise?" but "what made it rise?".
 */
function RiskTrend({
  history,
}: {
  history: Array<{ computed_at: string; score: number; level: RiskLevel; trigger?: string }>;
}) {
  if (history.length === 0) {
    return <p className="text-sm text-muted-foreground">No history yet.</p>;
  }

  return (
    <ol className="space-y-2">
      {history.map((point, index) => {
        const previous = index > 0 ? history[index - 1]!.score : null;
        const delta = previous === null ? null : point.score - previous;
        return (
          <li key={`${point.computed_at}-${index}`} className="flex items-baseline gap-3 text-sm">
            <span className="tabular w-24 shrink-0 text-xs text-muted-foreground">
              {formatTime(point.computed_at).split(", ")[1] ?? formatTime(point.computed_at)}
            </span>
            <span className="tabular w-8 shrink-0 text-right font-semibold">{point.score}</span>
            <span className="w-12 shrink-0">
              {delta !== null && delta !== 0 && (
                <span className={delta > 0 ? "text-sev-high" : "text-sev-low"}>
                  {delta > 0 ? `+${delta}` : delta}
                </span>
              )}
            </span>
            <Badge variant={riskVariant(point.level)}>{point.level}</Badge>
            <span className="truncate text-xs text-muted-foreground">{point.trigger}</span>
          </li>
        );
      })}
    </ol>
  );
}
