/**
 * The contract between the Electron main process and the renderer.
 *
 * Everything the renderer can ask for is enumerated here. Spec §6 requires the
 * renderer to have no direct access to fs, child_process, shell or net; the
 * only way across the boundary is one of these named channels.
 */

/** IPC channels exposed through the preload bridge. Nothing else is routable. */
export const CHANNELS = {
  deviceStatus: "netra:device-status",
  risk: "netra:risk",
  policy: "netra:policy",
  connection: "netra:connection",
} as const;

export type Channel = (typeof CHANNELS)[keyof typeof CHANNELS];

/**
 * Availability marker.
 *
 * A value that does not exist yet is reported as unavailable with the phase
 * that delivers it. Spec §48 forbids inventing a value to make the UI look
 * complete — and a security client that displays a fabricated trust score is
 * worse than one that admits it does not know.
 */
export type Available<T> =
  | { available: true; value: T }
  | { available: false; reason: string };

export interface DeviceStatus {
  hostname: string;
  deviceId: Available<string>;
  trustScore: Available<number>;
  agentConnected: boolean;
  agentVersion: Available<string>;
}

export interface RiskStatus {
  score: Available<number>;
  level: Available<string>;
  factors: string[];
  lastEvaluated: Available<string>;
}

export interface PolicyStatus {
  name: Available<string>;
  version: Available<number>;
  message: string;
}

export interface ConnectionStatus {
  backendUrl: string;
  reachable: boolean;
  environment?: string;
  backendVersion?: string;
  checkedAt: string;
  error?: string;
}

/** The API surface exposed on `window.netra`. */
export interface NetraBridge {
  getDeviceStatus(): Promise<DeviceStatus>;
  getRisk(): Promise<RiskStatus>;
  getPolicy(): Promise<PolicyStatus>;
  getConnectionStatus(): Promise<ConnectionStatus>;
}
