import { NotBuiltYet } from "@/components/layout/NotBuiltYet";
import { PageHeader } from "@/components/layout/PageHeader";

export function Endpoints() {
  return (
    <>
      <PageHeader title="Endpoints" description="Enrolled devices and their trust posture." />
      <NotBuiltYet
        phase="Phase 3 · 5"
        summary="Device records appear here once enrollment and posture collection are implemented."
        willShow={[
          "Hostname, device ID, assigned user and OS",
          "Device trust score with its contributing factors",
          "Agent version, last heartbeat and connection state",
          "Current session risk and applied policy",
        ]}
      />
    </>
  );
}

export function Users() {
  return (
    <>
      <PageHeader title="Users" description="Identity, sessions and behavioural context." />
      <NotBuiltYet
        phase="Phase 2 · 8"
        summary="User records are created from the identity provider once OIDC authentication is wired up."
        willShow={[
          "Department, role and enrolled devices",
          "Active sessions and recent authentication",
          "Behavioural anomalies against the user's baseline",
          "Recently accessed applications and resources",
        ]}
      />
    </>
  );
}

export function Sessions() {
  return (
    <>
      <PageHeader title="Sessions" description="Live user-and-device sessions under continuous evaluation." />
      <NotBuiltYet
        phase="Phase 4 · 7"
        summary="Sessions appear once the client binds a verified user to an attested device."
        willShow={[
          "Bound user and device with attestation status",
          "Current risk score and the factors behind it",
          "Risk history over the life of the session",
          "Policy decisions applied to the session",
        ]}
      />
    </>
  );
}

export function Incidents() {
  return (
    <>
      <PageHeader title="Incidents" description="Correlated security incidents and their attack paths." />
      <NotBuiltYet
        phase="Phase 12"
        summary="Correlation groups related events into a single incident rather than a stream of separate alerts."
        willShow={[
          "Severity, affected user, device and resource",
          "Peak risk score and the factors that drove it",
          "Event timeline and attack-path visualisation",
          "Policy action taken and analyst notes",
        ]}
      />
    </>
  );
}

export function Policies() {
  return (
    <>
      <PageHeader title="Policies" description="Versioned adaptive access policy." />
      <NotBuiltYet
        phase="Phase 9"
        summary="Policies are immutable versioned records, so every decision can cite the exact policy in force at the time."
        willShow={[
          "Conditions, actions, priority and fail mode",
          "Version history with author and timestamp",
          "Decisions made under each version",
          "Policy evaluation test harness",
        ]}
      />
    </>
  );
}

export function Audit() {
  return (
    <>
      <PageHeader title="Audit" description="Append-only record of privileged and security-relevant actions." />
      <NotBuiltYet
        phase="Phase 2 · 15"
        summary="The audit log is hash-chained: each record commits to its predecessor, so tampering is detectable."
        willShow={[
          "Actor, action, target and outcome",
          "Correlation by request ID to backend logs",
          "Authentication, enrollment and policy changes",
          "Chain verification status",
        ]}
      />
    </>
  );
}
