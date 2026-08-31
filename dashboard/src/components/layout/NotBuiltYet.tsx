import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

/**
 * Placeholder for a console section that is not implemented yet.
 *
 * Spec §48 forbids fabricated API responses that make the UI look finished.
 * An unbuilt page states which phase delivers it rather than showing invented
 * endpoints, users or incidents.
 */
export function NotBuiltYet({
  phase,
  summary,
  willShow,
}: {
  phase: string;
  summary: string;
  willShow: string[];
}) {
  return (
    <div className="p-8">
      <Card className="max-w-2xl">
        <CardHeader>
          <div className="flex items-center gap-3">
            <CardTitle>Not implemented yet</CardTitle>
            <Badge variant="outline">{phase}</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 text-sm text-muted-foreground">
          <p>{summary}</p>
          <div>
            <div className="mb-2 font-medium text-foreground">
              This page will show
            </div>
            <ul className="list-inside list-disc space-y-1">
              {willShow.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <p className="text-xs">
            No placeholder data is displayed here by design: the console shows
            only values the backend actually produced.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
