import { useState } from "react";
import type { SessionStatus } from "@shared/contract";

/**
 * Sign-in panel.
 *
 * Signing in requires the agent to attest this device, so a session cannot be
 * established from credentials alone. The access token never reaches this
 * component: it stays in the main process.
 */
export function SignIn({
  session,
  disabled,
  onChanged,
}: {
  session: SessionStatus | undefined;
  disabled: boolean;
  onChanged: () => Promise<void> | void;
}) {
  const [subject, setSubject] = useState("alice");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [detail, setDetail] = useState<string>();

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    setDetail(undefined);

    const result = await window.netra.signIn(subject);
    if (!result.ok) {
      setError(result.error ?? "Sign-in failed.");
      setDetail(result.detail);
    }
    await onChanged();
    setBusy(false);
  };

  const signOut = async () => {
    setBusy(true);
    await window.netra.signOut();
    await onChanged();
    setBusy(false);
  };

  if (session?.signedIn) {
    return (
      <section className="mt-6 rounded-lg border bg-card px-6 py-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="text-sm font-medium">Signed in as {session.subject}</div>
            <p className="mt-1 text-xs text-muted-foreground">
              Session bound to this device by {session.attestation ?? "attestation"}.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void signOut()}
            disabled={busy}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-card disabled:opacity-50"
          >
            Sign out
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="mt-6 rounded-lg border bg-card px-6 py-5">
      <form onSubmit={(e) => void submit(e)} className="flex items-end gap-3">
        <label className="flex-1 text-sm">
          <span className="mb-1.5 block text-muted-foreground">User</span>
          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            disabled={disabled || busy}
            spellCheck={false}
            autoComplete="off"
            className="w-full rounded-md border bg-transparent px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-ok/40 disabled:opacity-50"
          />
        </label>
        <button
          type="submit"
          disabled={disabled || busy || subject.trim() === ""}
          className="rounded-md border px-4 py-1.5 text-sm font-medium hover:bg-card disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>

      {error && (
        <div className="mt-3 text-sm text-bad">
          {error}
          {detail && <div className="mt-1 text-xs text-muted-foreground">{detail}</div>}
        </div>
      )}

      <p className="mt-3 text-xs text-muted-foreground">
        Development sign-in. Interactive sign-in with the organisational
        identity provider is not implemented yet.
      </p>
    </section>
  );
}
