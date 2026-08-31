import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { decisionVariant, formatTime, severityVariant } from "@/lib/risk";

export function Incidents() {
  const [selected, setSelected] = useState<string | null>(null);

  const incidents = useQuery({
    queryKey: ["incidents"],
    queryFn: api.incidents,
    refetchInterval: 5_000,
    retry: false,
  });

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Correlated escalations. One incident per session, not one alert per signal."
      />

      <div className="space-y-6 p-8">
        <Async isPending={incidents.isPending} error={incidents.error} data={incidents.data}>
          {({ incidents: list }) =>
            list.length === 0 ? (
              <Card className="max-w-xl">
                <CardHeader>
                  <CardTitle>No incidents</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  An incident opens when a policy that requires one matches a session.
                </CardContent>
              </Card>
            ) : (
              <>
                <Card>
                  <CardContent className="px-0 py-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Opened</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Peak risk</TableHead>
                          <TableHead>User</TableHead>
                          <TableHead>Device</TableHead>
                          <TableHead>Title</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {list.map((incident) => (
                          <TableRow
                            key={incident.id}
                            onClick={() => setSelected(incident.id === selected ? null : incident.id)}
                            className="cursor-pointer"
                          >
                            <TableCell className="tabular whitespace-nowrap text-muted-foreground">
                              {formatTime(incident.opened_at)}
                            </TableCell>
                            <TableCell>
                              <Badge variant={severityVariant(incident.severity)}>
                                {incident.severity}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline">{incident.status}</Badge>
                            </TableCell>
                            <TableCell className="tabular font-semibold">
                              {incident.peak_risk}
                            </TableCell>
                            <TableCell>{incident.user_name || "—"}</TableCell>
                            <TableCell>{incident.device_hostname || "—"}</TableCell>
                            <TableCell className="max-w-xs truncate">{incident.title}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {selected && <IncidentDetail incidentId={selected} />}
              </>
            )
          }
        </Async>
      </div>
    </>
  );
}

/**
 * One incident with the timeline that explains it.
 *
 * Events, risk changes and policy decisions are merged into a single ordered
 * narrative, because an analyst reconstructing what happened should not have to
 * cross-reference three separate lists by timestamp.
 */
function IncidentDetail({ incidentId }: { incidentId: string }) {
  const client = useQueryClient();

  const { data, isPending, error } = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => api.incident(incidentId),
    refetchInterval: 5_000,
    retry: false,
  });

  const setStatus = useMutation({
    mutationFn: (status: string) => api.setIncidentStatus(incidentId, status),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["incident", incidentId] });
      void client.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  return (
    <Async isPending={isPending} error={error} data={data}>
      {(detail) => (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <CardTitle>{detail.incident.title}</CardTitle>
                <div className="flex flex-wrap gap-2">
                  {(["INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"] as const).map(
                    (status) => (
                      <Button
                        key={status}
                        variant="outline"
                        size="sm"
                        disabled={setStatus.isPending || detail.incident.status === status}
                        onClick={() => setStatus.mutate(status)}
                      >
                        {status.replace("_", " ").toLowerCase()}
                      </Button>
                    ),
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p className="text-muted-foreground">{detail.incident.summary}</p>
              <dl className="grid gap-x-8 gap-y-1 sm:grid-cols-2 lg:grid-cols-4">
                <Field label="Severity" value={detail.incident.severity} />
                <Field label="Peak risk" value={String(detail.incident.peak_risk)} />
                <Field label="User" value={detail.incident.user_name || "—"} />
                <Field label="Device" value={detail.incident.device_hostname || "—"} />
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Attack path</CardTitle>
            </CardHeader>
            <CardContent>
              <Timeline detail={detail} />
            </CardContent>
          </Card>
        </div>
      )}
    </Async>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs tracking-wide text-muted-foreground uppercase">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
  );
}

interface TimelineEntry {
  at: string;
  kind: "event" | "risk" | "decision";
  label: string;
  detail: string;
  badge?: { text: string; variant: BadgeProps["variant"] };
}

function Timeline({ detail }: { detail: Awaited<ReturnType<typeof api.incident>> }) {
  const entries: TimelineEntry[] = [];

  for (const event of detail.events ?? []) {
    // Risk and policy events are rendered from their own richer records below.
    if (event.event_type === "RISK_UPDATE" || event.event_type === "POLICY_DECISION") continue;
    entries.push({
      at: event.occurred_at,
      kind: "event",
      label: event.event_type,
      detail: Object.entries(event.metadata ?? {})
        .filter(([key]) => !key.startsWith("netra."))
        .map(([key, value]) => `${key}=${value}`)
        .join("  "),
      badge: { text: event.severity, variant: severityVariant(event.severity) },
    });
  }

  for (const assessment of detail.risk_history ?? []) {
    entries.push({
      at: assessment.computed_at,
      kind: "risk",
      label: `Risk ${assessment.score}`,
      detail: assessment.factors.map((f) => `+${f.contribution} ${f.label}`).join("  ·  "),
      badge: { text: assessment.level, variant: severityVariant(assessment.level) },
    });
  }

  for (const decision of detail.decisions ?? []) {
    entries.push({
      at: decision.evaluated_at,
      kind: "decision",
      label: decision.decision,
      detail: `${decision.reason}${decision.policy_id ? ` · ${decision.policy_id} v${decision.policy_version}` : ""}`,
      badge: { text: "POLICY", variant: decisionVariant(decision.decision) },
    });
  }

  entries.sort((a, b) => a.at.localeCompare(b.at));

  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">No timeline entries.</p>;
  }

  return (
    <ol className="relative space-y-0 border-l pl-6">
      {entries.map((entry, index) => (
        <li key={`${entry.at}-${index}`} className="relative py-2.5">
          <span
            className={`absolute -left-[27px] top-4 size-2 rounded-full ${
              entry.kind === "decision"
                ? "bg-sev-critical"
                : entry.kind === "risk"
                  ? "bg-sev-elevated"
                  : "bg-muted-foreground"
            }`}
          />
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="tabular text-xs text-muted-foreground">{formatTime(entry.at)}</span>
            <span className="text-sm font-medium">{entry.label}</span>
            {entry.badge && <Badge variant={entry.badge.variant}>{entry.badge.text}</Badge>}
          </div>
          {entry.detail && (
            <p className="mt-0.5 text-xs text-muted-foreground">{entry.detail}</p>
          )}
        </li>
      ))}
    </ol>
  );
}
