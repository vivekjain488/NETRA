import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type DeviceSummary } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { formatTime, timeAgo } from "@/lib/risk";

/** Trust at or above this is counted as trusted, matching the backend. */
const TRUSTED_THRESHOLD = 70;

export function Endpoints() {
  const [selected, setSelected] = useState<string | null>(null);

  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: api.devices,
    refetchInterval: 10_000,
    retry: false,
  });

  return (
    <>
      <PageHeader title="Endpoints" description="Enrolled devices and their trust posture." />

      <div className="space-y-6 p-8">
        <Async isPending={devices.isPending} error={devices.error} data={devices.data}>
          {({ devices: list }) =>
            list.length === 0 ? (
              <Card className="max-w-xl">
                <CardHeader>
                  <CardTitle>No devices enrolled</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  Issue an enrollment token from the administrator API, then start an agent with it.
                </CardContent>
              </Card>
            ) : (
              <>
                <Card>
                  <CardContent className="px-0 py-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Hostname</TableHead>
                          <TableHead>State</TableHead>
                          <TableHead>Device trust</TableHead>
                          <TableHead>Key</TableHead>
                          <TableHead>Operating system</TableHead>
                          <TableHead>Agent</TableHead>
                          <TableHead>Last heartbeat</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {list.map((device) => (
                          <TableRow
                            key={device.id}
                            onClick={() => setSelected(device.id === selected ? null : device.id)}
                            className="cursor-pointer"
                          >
                            <TableCell className="font-medium">{device.hostname}</TableCell>
                            <TableCell>
                              <Badge variant={device.state === "ACTIVE" ? "low" : "critical"}>
                                {device.state}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <TrustCell device={device} />
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {device.key_protection}
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              {device.os_name} {device.os_version}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{device.agent_version}</TableCell>
                            <TableCell className="text-muted-foreground">
                              {timeAgo(device.last_heartbeat_at)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {selected && <PosturePanel deviceId={selected} />}
              </>
            )
          }
        </Async>
      </div>
    </>
  );
}

function TrustCell({ device }: { device: DeviceSummary }) {
  if (device.trust_score === undefined) {
    // Never reported is not the same as scoring zero, and must not read as it.
    return <span className="text-xs text-muted-foreground">not reported</span>;
  }
  const trusted = device.trust_score >= TRUSTED_THRESHOLD;
  return (
    <span className="inline-flex items-center gap-2">
      <span className="tabular font-semibold">{device.trust_score}</span>
      <span className="text-xs text-muted-foreground">/100</span>
      <Badge variant={trusted ? "low" : "high"}>{trusted ? "TRUSTED" : "AT RISK"}</Badge>
    </span>
  );
}

/** The explanation behind one device's trust score. */
function PosturePanel({ deviceId }: { deviceId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["posture", deviceId],
    queryFn: () => api.posture(deviceId),
    retry: false,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Device trust breakdown</CardTitle>
      </CardHeader>
      <CardContent>
        <Async isPending={isPending} error={error} data={data}>
          {(posture) => (
            <div className="space-y-4">
              <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
                <span className="tabular text-3xl font-semibold">{posture.trust_score}</span>
                <span className="text-sm text-muted-foreground">/ 100</span>
                <span className="font-mono text-xs text-muted-foreground">
                  {posture.model_version} · {formatTime(posture.collected_at)}
                </span>
                {!posture.verified && (
                  <Badge variant="outline">rests on endpoint claims</Badge>
                )}
              </div>

              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Control</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Finding</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {posture.factors.map((factor) => (
                    <TableRow key={factor.code}>
                      <TableCell className="font-medium">{factor.label}</TableCell>
                      <TableCell
                        className={
                          factor.contribution === 0
                            ? "tabular whitespace-nowrap text-sev-high"
                            : "tabular whitespace-nowrap"
                        }
                      >
                        {factor.contribution} / {factor.maximum}
                      </TableCell>
                      <TableCell>
                        <span
                          className={
                            factor.source === "verified"
                              ? "font-mono text-xs text-sev-low"
                              : "font-mono text-xs text-muted-foreground"
                          }
                        >
                          {factor.source}
                        </span>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{factor.detail}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              <p className="text-xs text-muted-foreground">
                Signals marked <span className="font-mono">reported</span> are endpoint claims.
                NETRA scores them, but only what it established itself is marked{" "}
                <span className="font-mono">verified</span>.
              </p>
            </div>
          )}
        </Async>
      </CardContent>
    </Card>
  );
}
