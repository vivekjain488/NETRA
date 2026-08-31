import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { signIn } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Sign-in for the SOC console.
 *
 * Every operational endpoint requires a role, so the console asks for an
 * identity before it shows anything rather than rendering a page of permission
 * errors. The token is held in memory by the API client and never written to
 * storage: a credential on disk outlives the tab that needed it.
 */
export function SignInGate({ onSignedIn }: { onSignedIn: () => void }) {
  const client = useQueryClient();
  const [subject, setSubject] = useState("ravi");
  const [role, setRole] = useState("SECURITY_ANALYST");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await signIn(subject, [role]);
      await client.invalidateQueries();
      onSignedIn();
    } catch {
      setError(
        "Sign-in failed. The backend offers development authentication only when NETRA_ENV=development.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-8">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-base">NETRA Security Operations</CardTitle>
          <CardDescription>
            Sign in to investigate endpoints, sessions and incidents.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => void submit(e)} className="space-y-4">
            <label className="block text-sm">
              <span className="mb-1.5 block text-muted-foreground">Analyst</span>
              <input
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                className="w-full rounded-md border bg-transparent px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
              />
            </label>

            <label className="block text-sm">
              <span className="mb-1.5 block text-muted-foreground">Role</span>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full rounded-md border bg-transparent px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="SECURITY_ANALYST">Security analyst</option>
                <option value="ADMIN">Administrator</option>
                <option value="AUDITOR">Auditor</option>
                <option value="USER">Ordinary user</option>
              </select>
            </label>

            <Button type="submit" disabled={busy || subject.trim() === ""} className="w-full">
              {busy ? "Signing in…" : "Sign in"}
            </Button>

            {error && <p className="text-sm text-sev-critical">{error}</p>}

            <p className="text-xs text-muted-foreground">
              Development sign-in. Interactive sign-in with the organisational identity provider is
              not implemented yet. Choosing an ordinary user is useful for confirming that
              role-based access control actually refuses access.
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
