import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { formatTime } from "@/lib/risk";

export function Audit() {
  const { data, isPending, error } = useQuery({
    queryKey: ["audit"],
    queryFn: api.audit,
    refetchInterval: 10_000,
    retry: false,
  });

  return (
    <>
      <PageHeader
        title="Audit"
        description="Append-only record of privileged and security-relevant actions."
      />

      <div className="space-y-6 p-8">
        <Async isPending={isPending} error={error} data={data}>
          {(page) => (
            <>
              {/*
                Chain integrity leads the page. An analyst reading an audit log
                needs to know whether it can be trusted before drawing any
                conclusion from what it says.
              */}
              <Card
                className={page.chain_verified ? "border-sev-low/40" : "border-sev-critical/60"}
              >
                <CardHeader>
                  <div className="flex flex-wrap items-center gap-3">
                    <CardTitle>
                      {page.chain_verified ? "Chain intact" : "Chain broken"}
                    </CardTitle>
                    <Badge variant={page.chain_verified ? "low" : "critical"}>
                      {page.chain_verified ? "VERIFIED" : "TAMPERED"}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  {page.chain_verified ? (
                    <>
                      Every record commits to its predecessor&apos;s hash, and all{" "}
                      {page.records.length} records reconcile. Removing, reordering or editing any
                      entry would break the chain from that point on.
                    </>
                  ) : (
                    <span className="text-sev-critical">{page.chain_error}</span>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardContent className="px-0 py-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Seq</TableHead>
                        <TableHead>Time</TableHead>
                        <TableHead>Actor</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Result</TableHead>
                        <TableHead>Hash</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {[...page.records].reverse().map((record) => (
                        <TableRow key={record.seq}>
                          <TableCell className="tabular text-muted-foreground">
                            {record.seq}
                          </TableCell>
                          <TableCell className="tabular whitespace-nowrap text-muted-foreground">
                            {formatTime(record.at)}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {record.actor_type}
                            {record.actor_id ? ` ${record.actor_id.slice(0, 8)}` : ""}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{record.action}</TableCell>
                          <TableCell className="max-w-[16rem] truncate font-mono text-xs text-muted-foreground">
                            {record.target_id ?? "—"}
                          </TableCell>
                          <TableCell>
                            <Badge variant={record.result === "SUCCESS" ? "low" : "high"}>
                              {record.result}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {record.hash.slice(0, 12)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </>
          )}
        </Async>
      </div>
    </>
  );
}
