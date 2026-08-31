import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { formatTime, severityVariant } from "@/lib/risk";

const FILTERS = [
  { label: "All", query: "" },
  { label: "Risk", query: "?type=RISK_UPDATE" },
  { label: "Policy", query: "?type=POLICY_DECISION" },
  { label: "Activity", query: "?type=APPLICATION_START,NETWORK_EVENT" },
  { label: "High and above", query: "?severity=HIGH" },
] as const;

export function Events() {
  const [filter, setFilter] = useState<string>("");

  const { data, isPending, error } = useQuery({
    queryKey: ["events", filter],
    queryFn: () => api.events(filter),
    refetchInterval: 5_000,
    retry: false,
  });

  return (
    <>
      <PageHeader
        title="Events"
        description="The normalized security event stream, from endpoints and from the control plane."
      />

      <div className="space-y-4 p-8">
        <div className="flex flex-wrap gap-2">
          {FILTERS.map((option) => (
            <Button
              key={option.label}
              variant={filter === option.query ? "default" : "outline"}
              size="sm"
              onClick={() => setFilter(option.query)}
            >
              {option.label}
            </Button>
          ))}
        </div>

        <Card>
          <CardContent className="px-0 py-0">
            <Async isPending={isPending} error={error} data={data}>
              {({ events }) =>
                events.length === 0 ? (
                  <p className="p-5 text-sm text-muted-foreground">
                    No events match this filter.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Occurred</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Endpoint</TableHead>
                        <TableHead>User</TableHead>
                        <TableHead>Metadata</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {events.map((event) => (
                        <TableRow key={event.id}>
                          <TableCell className="tabular whitespace-nowrap text-muted-foreground">
                            {formatTime(event.occurred_at)}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{event.event_type}</TableCell>
                          <TableCell>
                            <Badge variant={severityVariant(event.severity)}>{event.severity}</Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {event.source}
                          </TableCell>
                          <TableCell>{event.device_hostname || "—"}</TableCell>
                          <TableCell>{event.user_name || "—"}</TableCell>
                          <TableCell className="max-w-md truncate font-mono text-xs text-muted-foreground">
                            {Object.entries(event.metadata ?? {})
                              .map(([key, value]) => `${key}=${value}`)
                              .join("  ")}
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
