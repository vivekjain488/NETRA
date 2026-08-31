import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { decisionVariant, formatTime } from "@/lib/risk";

export function Policies() {
  const policies = useQuery({ queryKey: ["policies"], queryFn: api.policies, retry: false });
  const decisions = useQuery({
    queryKey: ["decisions"],
    queryFn: api.decisions,
    refetchInterval: 5_000,
    retry: false,
  });

  return (
    <>
      <PageHeader
        title="Policies"
        description="Versioned adaptive access policy, and the decisions made under it."
      />

      <div className="space-y-6 p-8">
        <Card>
          <CardHeader>
            <CardTitle>Policy set</CardTitle>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <Async isPending={policies.isPending} error={policies.error} data={policies.data}>
              {({ policies: list }) => (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Policy</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Applies when</TableHead>
                      <TableHead>Decision</TableHead>
                      <TableHead>On outage</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {list.map((policy) => (
                      <TableRow key={`${policy.policy_id}-${policy.version}`}>
                        <TableCell>
                          <div className="font-medium">{policy.name}</div>
                          <div className="font-mono text-xs text-muted-foreground">
                            {policy.policy_id}
                          </div>
                        </TableCell>
                        <TableCell className="tabular">v{policy.version}</TableCell>
                        <TableCell className="tabular text-muted-foreground">
                          {policy.priority}
                        </TableCell>
                        <TableCell className="max-w-xs text-xs text-muted-foreground">
                          {describeConditions(policy.conditions)}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap items-center gap-1.5">
                            <Badge variant={decisionVariant(policy.actions.decision)}>
                              {policy.actions.decision}
                            </Badge>
                            {policy.actions.create_incident && (
                              <Badge variant="outline">incident</Badge>
                            )}
                            {policy.actions.alert_soc && <Badge variant="outline">alert</Badge>}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {policy.fail_mode}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Async>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent decisions</CardTitle>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <Async isPending={decisions.isPending} error={decisions.error} data={decisions.data}>
              {({ decisions: list }) =>
                list.length === 0 ? (
                  <p className="px-5 pb-5 text-sm text-muted-foreground">
                    No decisions have been made yet.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Time</TableHead>
                        <TableHead>Decision</TableHead>
                        <TableHead>User</TableHead>
                        <TableHead>Device</TableHead>
                        <TableHead>Policy</TableHead>
                        <TableHead>Reason</TableHead>
                        <TableHead>Latency</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {list.map((decision) => (
                        <TableRow key={decision.id}>
                          <TableCell className="tabular whitespace-nowrap text-muted-foreground">
                            {formatTime(decision.evaluated_at)}
                          </TableCell>
                          <TableCell>
                            <Badge variant={decisionVariant(decision.decision)}>
                              {decision.decision}
                            </Badge>
                          </TableCell>
                          <TableCell>{decision.user_name || "—"}</TableCell>
                          <TableCell>{decision.device_hostname || "—"}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {decision.policy_id ? `${decision.policy_id} v${decision.policy_version}` : "—"}
                          </TableCell>
                          <TableCell className="max-w-xs truncate text-muted-foreground">
                            {decision.reason}
                          </TableCell>
                          {/* Policy evaluation sits in the access path, so its
                              cost belongs on screen rather than in a benchmark. */}
                          <TableCell className="tabular whitespace-nowrap text-xs text-muted-foreground">
                            {decision.latency_us} µs
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )
              }
            </Async>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

/** Renders a policy's conditions as the sentence an operator would say. */
function describeConditions(conditions: Record<string, unknown>): string {
  const parts: string[] = [];
  const levels = conditions.levels as string[] | undefined;
  const sensitivity = conditions.resource_sensitivity as string[] | undefined;
  const factors = conditions.require_factors as string[] | undefined;
  const min = conditions.min_risk as number | undefined;
  const max = conditions.max_risk as number | undefined;

  if (levels?.length) parts.push(`risk level ${levels.join(" or ")}`);
  if (min !== undefined) parts.push(`risk ≥ ${min}`);
  if (max !== undefined) parts.push(`risk ≤ ${max}`);
  if (sensitivity?.length) parts.push(`resource is ${sensitivity.join(" or ")}`);
  if (factors?.length) parts.push(`factors present: ${factors.join(", ")}`);

  return parts.join(" and ") || "any session";
}
