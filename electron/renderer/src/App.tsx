import { useEffect, useState } from "react";
import type {
  ConnectionStatus,
  DeviceStatus,
  PolicyStatus,
  RiskStatus,
} from "@shared/contract";
import { StatusRow } from "@/components/StatusRow";

/**
 * The Home screen from spec §7.
 *
 * Every field is read through `window.netra`. Values that the platform cannot
 * yet produce are shown as unavailable with the phase that delivers them,
 * rather than as a plausible-looking placeholder.
 */
export function App() {
  const [device, setDevice] = useState<DeviceStatus>();
  const [risk, setRisk] = useState<RiskStatus>();
  const [policy, setPolicy] = useState<PolicyStatus>();
  const [connection, setConnection] = useState<ConnectionStatus>();

  useEffect(() => {
    let cancelled = false;

    const refresh = async () => {
      const [d, r, p, c] = await Promise.all([
        window.netra.getDeviceStatus(),
        window.netra.getRisk(),
        window.netra.getPolicy(),
        window.netra.getConnectionStatus(),
      ]);
      if (cancelled) return;
      setDevice(d);
      setRisk(r);
      setPolicy(p);
      setConnection(c);
    };

    void refresh();
    const timer = setInterval(() => void refresh(), 15_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="mx-auto flex min-h-screen max-w-2xl flex-col px-8 py-10">
      <header className="mb-8">
        <h1 className="text-xl font-semibold tracking-wide">NETRA</h1>
        <p className="text-sm text-muted-foreground">Continuous security</p>
      </header>

      <section className="rounded-lg border bg-card px-6 py-2">
        <dl className="divide-y">
          <StatusRow
            label="User"
            value={{
              available: false,
              reason: "Sign-in arrives in Phase 2",
            }}
          />
          <StatusRow label="Device" value={device?.hostname ?? "…"} />
          <StatusRow
            label="Device trust"
            value={device?.trustScore ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Session risk"
            value={risk?.score ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Agent"
            value={device?.agentConnected ? "Connected" : "Not connected"}
            tone={device?.agentConnected ? "ok" : undefined}
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
            tone={
              connection === undefined ? undefined : connection.reachable ? "ok" : "bad"
            }
          />
          <StatusRow
            label="Policy"
            value={policy?.name ?? { available: false, reason: "…" }}
          />
          <StatusRow
            label="Last sync"
            value={
              connection
                ? new Date(connection.checkedAt).toLocaleTimeString()
                : "…"
            }
          />
        </dl>
      </section>

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
