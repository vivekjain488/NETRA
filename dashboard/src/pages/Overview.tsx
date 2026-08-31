import { useQuery } from "@tanstack/react-query";
import { getReadiness, type HealthResponse } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";

/**
 * Overview.
 *
 * Every value on this page comes from a live backend response. The fleet
 * counters required by spec §29 are added in Phase 10, once devices and
 * incidents exist to count — they are not stubbed with invented numbers.
 */
export function Overview() {
  const { data, isError, isPending, error } = useQuery({
    queryKey: ["readiness"],
    queryFn: getReadiness,
    refetchInterval: 10_000,
    retry: false,
  });

  return (
    <>
      <PageHeader
        title="Overview"
        description="Control plane status and build information."
      />

      <div className="p-8">
        {isPending && <StatusCard title="Connecting to the control plane…" />}

        {isError && (
          <StatusCard
            title="Backend unreachable"
            tone="critical"
            detail={
              error instanceof Error
                ? error.message
                : "The console could not reach the NETRA backend."
            }
          />
        )}

        {data && <ControlPlaneCard health={data} />}
      </div>
    </>
  );
}

function ControlPlaneCard({ health }: { health: HealthResponse }) {
  const healthy = health.status === "ok";

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <CardTitle>Control plane</CardTitle>
            <Badge variant={healthy ? "low" : "high"}>
              {healthy ? "ONLINE" : "DEGRADED"}
            </Badge>
          </div>
          <CardDescription>Reported by the readiness endpoint.</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-y-2 text-sm">
            <Field label="Environment" value={health.env} />
            <Field label="Uptime" value={health.uptime} />
            <Field label="Version" value={health.build.version} />
            <Field label="Commit" value={health.build.commit} mono />
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Dependencies</CardTitle>
          <CardDescription>Live checks from the backend.</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-y-2 text-sm">
            {Object.entries(health.checks).map(([name, value]) => (
              <Field key={name} label={name} value={value} />
            ))}
            {Object.keys(health.checks).length === 0 && (
              <dd className="col-span-2 text-muted-foreground">
                No dependency checks reported.
              </dd>
            )}
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Fleet</CardTitle>
          <CardDescription>Endpoint and incident counters.</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Available once device enrollment (Phase 3) and incidents (Phase 12)
          are implemented. No figures are shown until they are real.
        </CardContent>
      </Card>
    </div>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="text-muted-foreground capitalize">{label}</dt>
      <dd className={mono ? "truncate font-mono text-xs" : "truncate"}>{value}</dd>
    </>
  );
}

function StatusCard({
  title,
  detail,
  tone,
}: {
  title: string;
  detail?: string;
  tone?: "critical";
}) {
  return (
    <Card className="max-w-xl">
      <CardHeader>
        <div className="flex items-center gap-3">
          <CardTitle>{title}</CardTitle>
          {tone === "critical" && <Badge variant="critical">OFFLINE</Badge>}
        </div>
        {detail && <CardDescription>{detail}</CardDescription>}
      </CardHeader>
    </Card>
  );
}
