import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type ScenarioResult } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { Async } from "@/components/soc/Async";
import { decisionVariant, severityVariant } from "@/lib/risk";

/**
 * Demonstration controls.
 *
 * Each scenario generates real events that travel the real ingest path, the
 * real risk engine and the real policy engine. Nothing on this page writes a
 * score, a decision or an incident directly — the numbers below are read back
 * from what the platform decided.
 */
export function Demo() {
  const client = useQueryClient();
  const [result, setResult] = useState<ScenarioResult>();

  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios, retry: false });

  const run = useMutation({
    mutationFn: (name: string) => api.runScenario(name),
    onSuccess: (data) => {
      setResult(data);
      // The scenario changed real state, so every other view is now stale.
      void client.invalidateQueries();
    },
  });

  return (
    <>
      <PageHeader
        title="Demonstration"
        description="Trigger synthetic activity through the live pipeline."
      />

      <div className="space-y-6 p-8">
        <Async isPending={scenarios.isPending} error={scenarios.error} data={scenarios.data}>
          {(data) => (
            <>
              <p className="max-w-3xl text-sm text-muted-foreground">{data.notice}</p>

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                {data.scenarios.map((scenario) => (
                  <Card key={scenario.name} className="flex flex-col">
                    <CardHeader>
                      <CardTitle>{scenario.title}</CardTitle>
                      <CardDescription>{scenario.description}</CardDescription>
                    </CardHeader>
                    <CardContent className="mt-auto space-y-3">
                      <p className="text-xs text-muted-foreground">{scenario.expectation}</p>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={run.isPending}
                        onClick={() => run.mutate(scenario.name)}
                        className="w-full"
                      >
                        {run.isPending && run.variables === scenario.name ? "Running…" : "Run"}
                      </Button>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {run.isError && (
                <p className="text-sm text-sev-critical">
                  The scenario could not be completed. Check the backend logs.
                </p>
              )}

              {result && <ScenarioTrace result={result} />}
            </>
          )}
        </Async>
      </div>
    </>
  );
}

/** What the platform decided, step by step. */
function ScenarioTrace({ result }: { result: ScenarioResult }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle>{result.scenario}</CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            <span className="tabular text-2xl font-semibold">{result.final_score}</span>
            <Badge variant={severityVariant(result.final_level)}>{result.final_level}</Badge>
            <Badge variant={decisionVariant(result.final_decision)}>{result.final_decision}</Badge>
          </div>
        </div>
        <CardDescription>
          {result.user} on {result.device}
          {result.incident_id && " · incident opened"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ol className="space-y-0 divide-y">
          {result.steps.map((step, index) => {
            const previous = index > 0 ? result.steps[index - 1]?.risk_score : undefined;
            const delta =
              previous === undefined || step.risk_score === undefined
                ? undefined
                : step.risk_score - previous;

            return (
              <li key={`${step.step}-${index}`} className="py-3">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className="tabular w-8 shrink-0 text-right text-lg font-semibold">
                    {step.risk_score ?? "—"}
                  </span>
                  <span className="tabular w-10 shrink-0 text-sm">
                    {delta !== undefined && delta !== 0 && (
                      <span className={delta > 0 ? "text-sev-high" : "text-sev-low"}>
                        {delta > 0 ? `+${delta}` : delta}
                      </span>
                    )}
                  </span>
                  <span className="min-w-0 flex-1 text-sm font-medium">{step.step}</span>
                  {step.risk_level && (
                    <Badge variant={severityVariant(step.risk_level)}>{step.risk_level}</Badge>
                  )}
                  {step.decision && (
                    <Badge variant={decisionVariant(step.decision)}>{step.decision}</Badge>
                  )}
                </div>
                {step.factors && step.factors.length > 0 && (
                  <p className="mt-1 pl-[4.75rem] font-mono text-xs text-muted-foreground">
                    {step.factors.join("  ·  ")}
                  </p>
                )}
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}
