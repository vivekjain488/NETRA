import { useCallback, useEffect, useState } from "react";
import type {
  ConnectionStatus,
  DeviceStatus,
  PolicyStatus,
  RiskStatus,
  SessionStatus,
} from "@shared/contract";
import { StatusRow } from "@/components/StatusRow";
import { SignIn } from "@/components/SignIn";

/**
 * The Home screen from spec §7.
 *
 * Every field is read through `window.netra`. Values the platform cannot yet
 * produce are shown as unavailable with the phase that delivers them, rather
 * than as a plausible-looking placeholder.
 */
export function App() {
  const [device, setDevice] = useState<DeviceStatus>();
  const [risk, setRisk] = useState<RiskStatus>();
  const [policy, setPolicy] = useState<PolicyStatus>();
  const [connection, setConnection] = useState<ConnectionStatus>();
  const [session, setSession] = useState<SessionStatus>();

  const refresh = useCallback(async () => {
    const [d, r, p, c, s] = await Promise.all([
      window.netra.getDeviceStatus(),
      window.netra.getRisk(),
      window.netra.getPolicy(),
      window.netra.getConnectionStatus(),
      window.netra.getSession(),
    ]);
    setDevice(d);
    setRisk(r);
    setPolicy(p);
    setConnection(c);
    setSession(s);
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 15_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const agentDown = device !== undefined && !device.agentConnected;

  return (
    <div className="mx-auto flex min-h-screen max-w-2xl flex-col px-8 py-10">
      <header className="mb-8">
        <h1 className="text-xl font-semibold tracking-wide">NETRA</h1>
        <p className="text-sm text-muted-foreground">Continuous security</p>
      </header>

      {device?.identityRevoked && (
        <div className="mb-6 rounded-md border border-bad/40 bg-bad/10 px-4 py-3 text-sm">
          <div className="font-medium text-bad">This device is no longer trusted</div>
          <p className="mt-1 text-muted-foreground">
            The control plane has withdrawn this device&apos;s identity. Contact
            your administrator.
          </p>
        </div>
      )}

      {agentDown && !device?.identityRevoked && (
        <div className="mb-6 rounded-md border border-warn/40 bg-warn/10 px-4 py-3 text-sm">
          <div className="font-medium text-warn">The security agent is not running</div>
          <p className="mt-1 text-muted-foreground">
            Device status cannot be confirmed and sign-in is unavailable.
          </p>
        </div>
      )}

      <section className="rounded-lg border bg-card px-6 py-2">
        <dl className="divide-y">
          <StatusRow
            label="User"
            value={
              session?.signedIn && session.subject
                ? session.subject
                : { available: false, reason: "Not signed in" }
            }
          />
          <StatusRow label="Device" value={device?.hostname ?? "…"} />
          <StatusRow
            label="Device identity"
            value={device?.deviceId ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Key protection"
            value={device?.keyProtection ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Device trust"
            value={device?.trustScore ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Session risk"
            value={risk?.score ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Session"
            value={
              session?.signedIn
                ? `${session.status ?? "ACTIVE"} · device attested`
                : { available: false, reason: "No active session" }
            }
            tone={session?.signedIn ? "ok" : undefined}
          />
          <StatusRow
            label="Agent"
            value={device?.agentConnected ? "Running" : "Not running"}
            tone={device?.agentConnected ? "ok" : "warn"}
          />
          <StatusRow
            label="Queued events"
            value={device?.queuedEvents ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Control plane"
            value={
              connection === undefined
                ? "Checking…"
                : connection.reachable
                  ? `Connected · ${connection.backendVersion ?? "unknown build"}`
                  : "Unreachable"
            }
            tone={connection === undefined ? undefined : connection.reachable ? "ok" : "bad"}
          />
          <StatusRow
            label="Policy"
            value={policy?.name ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Last sync"
            value={connection ? new Date(connection.checkedAt).toLocaleTimeString() : "…"}
          />
        </dl>
      </section>

      {device && device.trustWeaknesses.length > 0 && (
        <section className="mt-6 rounded-lg border bg-card px-6 py-5">
          <div className="text-sm font-medium">What is reducing device trust</div>
          <ul className="mt-2 space-y-1.5 text-sm text-muted-foreground">
            {device.trustWeaknesses.map((weakness) => (
              <li key={weakness}>{weakness}</li>
            ))}
          </ul>
        </section>
      )}

      <SignIn session={session} disabled={agentDown} onChanged={refresh} />

      <p className="mt-6 text-xs leading-relaxed text-muted-foreground">
        NETRA collects security metadata only — authentication, device posture,
        application and resource access. It does not capture keystrokes, screen
        contents, messages, camera or microphone.
      </p>

      <div className="mt-auto pt-8 text-xs text-muted-foreground">
        {connection?.backendUrl}
      </div>
    </div>
  );
}
