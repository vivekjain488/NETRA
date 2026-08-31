/**
 * IPC handlers.
 *
 * Each handler is registered against a fixed channel from the shared contract.
 * Handlers take no arguments in Phase 1; when they do, arguments will be
 * validated here rather than trusted, because the renderer is the least
 * trusted part of this process tree.
 */

import { ipcMain } from "electron";
import {
  CHANNELS,
  type ConnectionStatus,
  type DeviceStatus,
  type PolicyStatus,
  type RiskStatus,
} from "../shared/contract";

/** Anything not yet implemented says so, naming the phase that delivers it. */
const pending = (phase: string) => ({
  available: false as const,
  reason: `Not available until ${phase}`,
});

export interface IpcDeps {
  backendUrl: string;
  hostname: string;
}

export function registerIpcHandlers(deps: IpcDeps): void {
  ipcMain.handle(CHANNELS.deviceStatus, async (): Promise<DeviceStatus> => ({
    hostname: deps.hostname,
    // Populated once the agent IPC channel exists (Phase 4) and the device is
    // enrolled (Phase 3). The client never invents a device identity.
    deviceId: pending("Phase 3 (device enrollment)"),
    trustScore: pending("Phase 5 (device posture)"),
    agentConnected: false,
    agentVersion: pending("Phase 4 (client to agent IPC)"),
  }));

  ipcMain.handle(CHANNELS.risk, async (): Promise<RiskStatus> => ({
    score: pending("Phase 7 (risk engine)"),
    level: pending("Phase 7 (risk engine)"),
    factors: [],
    lastEvaluated: pending("Phase 7 (risk engine)"),
  }));

  ipcMain.handle(CHANNELS.policy, async (): Promise<PolicyStatus> => ({
    name: pending("Phase 9 (policy engine)"),
    version: pending("Phase 9 (policy engine)"),
    message: "No policy has been applied to this session yet.",
  }));

  ipcMain.handle(CHANNELS.connection, async (): Promise<ConnectionStatus> =>
    checkBackend(deps.backendUrl),
  );
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
