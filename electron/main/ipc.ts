/**
 * IPC handlers.
 *
 * Each handler is registered against a fixed channel from the shared contract.
 * Arguments coming from the renderer are validated here rather than trusted:
 * the renderer is the least trusted part of this process tree.
 */

import { ipcMain } from "electron";
import {
  CHANNELS,
  type ConnectionStatus,
  type DeviceStatus,
  type PolicyStatus,
  type RiskStatus,
  type SessionStatus,
  type SignInResult,
} from "../shared/contract";
import { AgentClient, AgentUnavailableError, type AgentStatus } from "./agent";
import { SessionManager, SignInError } from "./session";

/** Anything not yet implemented says so, naming the phase that delivers it. */
const pending = (phase: string) => ({
  available: false as const,
  reason: `Not available until ${phase}`,
});

const unavailable = (reason: string) => ({ available: false as const, reason });

/** Subjects are constrained here so the renderer cannot send anything odd. */
const SUBJECT_PATTERN = /^[a-zA-Z0-9._-]{1,64}$/;

export interface IpcDeps {
  backendUrl: string;
  hostname: string;
  agent: AgentClient;
  sessions: SessionManager;
}

export function registerIpcHandlers(deps: IpcDeps): void {
  ipcMain.handle(CHANNELS.deviceStatus, async (): Promise<DeviceStatus> => {
    let status: AgentStatus | null = null;
    try {
      status = await deps.agent.status();
    } catch {
      // The agent being down is a normal state to display, not an error to
      // throw at the user interface.
    }

    if (!status) {
      return {
        hostname: deps.hostname,
        deviceId: unavailable("The NETRA agent is not running"),
        trustScore: pending("Phase 5 (device posture)"),
        agentConnected: false,
        agentVersion: unavailable("The NETRA agent is not running"),
        keyProtection: unavailable("The NETRA agent is not running"),
        identityRevoked: false,
        queuedEvents: unavailable("The NETRA agent is not running"),
      };
    }

    return {
      hostname: status.hostname || deps.hostname,
      deviceId: status.device_id
        ? { available: true, value: status.device_id }
        : unavailable("This device is not enrolled"),
      // Posture scoring arrives in Phase 5; the client does not invent a score.
      trustScore: pending("Phase 5 (device posture)"),
      agentConnected: true,
      agentVersion: { available: true, value: status.agent_version },
      keyProtection: { available: true, value: status.key_protection },
      identityRevoked: status.identity_rejected,
      queuedEvents: { available: true, value: status.queued_events },
    };
  });

  ipcMain.handle(CHANNELS.risk, async (): Promise<RiskStatus> => {
    const session = deps.sessions.current();
    if (session?.current_risk !== undefined && session.current_risk !== null) {
      return {
        score: { available: true, value: session.current_risk },
        level: session.risk_level
          ? { available: true, value: session.risk_level }
          : pending("Phase 7 (risk engine)"),
        factors: [],
        lastEvaluated: pending("Phase 7 (risk engine)"),
      };
    }
    return {
      score: pending("Phase 7 (risk engine)"),
      level: pending("Phase 7 (risk engine)"),
      factors: [],
      lastEvaluated: pending("Phase 7 (risk engine)"),
    };
  });

  ipcMain.handle(CHANNELS.policy, async (): Promise<PolicyStatus> => ({
    name: pending("Phase 9 (policy engine)"),
    version: pending("Phase 9 (policy engine)"),
    message: "No policy has been applied to this session yet.",
  }));

  ipcMain.handle(CHANNELS.connection, async (): Promise<ConnectionStatus> =>
    checkBackend(deps.backendUrl),
  );

  ipcMain.handle(CHANNELS.session, async (): Promise<SessionStatus> => toSessionStatus(deps));

  ipcMain.handle(CHANNELS.signIn, async (_event, subject: unknown): Promise<SignInResult> => {
    if (typeof subject !== "string" || !SUBJECT_PATTERN.test(subject)) {
      return { ok: false, error: "That user name is not valid." };
    }

    try {
      await deps.sessions.signIn(subject);
      return { ok: true, session: toSessionStatus(deps) };
    } catch (error) {
      if (error instanceof SignInError || error instanceof AgentUnavailableError) {
        return {
          ok: false,
          error: error.message,
          detail: error instanceof SignInError ? error.cause : undefined,
        };
      }
      return { ok: false, error: "Sign-in could not be completed." };
    }
  });

  ipcMain.handle(CHANNELS.signOut, async (): Promise<SessionStatus> => {
    await deps.sessions.signOut();
    return toSessionStatus(deps);
  });
}

function toSessionStatus(deps: IpcDeps): SessionStatus {
  const session = deps.sessions.current();
  if (!session) {
    return { signedIn: false };
  }
  return {
    signedIn: true,
    subject: deps.sessions.currentSubject() ?? undefined,
    sessionId: session.id,
    status: session.status,
    attestation: session.attestation,
    startedAt: session.started_at,
  };
}

/**
 * Queries backend liveness.
 *
 * Network access lives in the main process: the renderer has no `net` access
 * at all, so it cannot reach the backend except through this channel.
 */
export async function checkBackend(backendUrl: string): Promise<ConnectionStatus> {
  const checkedAt = new Date().toISOString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(`${backendUrl}/api/v1/health`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      return {
        backendUrl,
        reachable: false,
        checkedAt,
        error: `Backend responded with status ${response.status}`,
      };
    }
    const body = (await response.json()) as {
      env?: string;
      build?: { version?: string };
    };
    return {
      backendUrl,
      reachable: true,
      environment: body.env,
      backendVersion: body.build?.version,
      checkedAt,
    };
  } catch (error) {
    return {
      backendUrl,
      reachable: false,
      checkedAt,
      error: error instanceof Error ? error.message : "Backend unreachable",
    };
  } finally {
    clearTimeout(timeout);
  }
}
