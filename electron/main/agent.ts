/**
 * Client to the NETRA agent's local IPC endpoint.
 *
 * The client process holds no device key. When it needs proof that this
 * machine is an enrolled device, it asks the agent, which signs on its behalf.
 * The agent constructs the attestation message itself, so this channel cannot
 * be used to obtain a signature over arbitrary bytes.
 *
 * Everything here runs in the **main** process. The renderer has no access to
 * `net` or `fs`, so it cannot reach the agent except through the preload
 * bridge.
 */

import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

/** How long to wait for the agent before treating it as unavailable. */
const REQUEST_TIMEOUT_MS = 5000;

/** The agent's report on itself. */
export interface AgentStatus {
  enrolled: boolean;
  device_id: string | null;
  device_uid: string | null;
  key_protection: string;
  hostname: string;
  os_name: string;
  os_version: string;
  agent_version: string;
  backend_url: string;
  connected: boolean;
  identity_rejected: boolean;
  last_heartbeat: string | null;
  queued_events: number;
  dropped_events: number;
}

/** A device attestation for one sign-in. */
export interface Attestation {
  device_uid: string;
  signature: string;
}

interface AgentResponse<T> {
  ok: boolean;
  result?: T;
  error?: string;
}

/** Raised when the agent cannot be reached or refuses a request. */
export class AgentUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentUnavailableError";
  }
}

/** Resolves the agent's state directory, matching the agent's own logic. */
export function agentStateDir(): string {
  const explicit = process.env.NETRA_AGENT_STATE_DIR;
  if (explicit && explicit.trim() !== "") {
    return explicit;
  }
  if (process.platform === "win32") {
    const local = process.env.LOCALAPPDATA;
    if (local) return path.join(local, "NETRA");
  }
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support", "NETRA");
  }
  return path.join(os.homedir(), ".netra");
}

/**
 * Resolves the endpoint the agent listens on.
 *
 * The agent publishes its actual endpoint to `agent.endpoint`, which is read in
 * preference to re-deriving it here: on Unix the agent falls back to a short
 * path in the temporary directory when the state directory would overflow
 * `sockaddr_un.sun_path`, and the client must follow it there.
 */
export async function agentEndpoint(stateDir: string): Promise<string> {
  try {
    const published = (await fs.readFile(path.join(stateDir, "agent.endpoint"), "utf8")).trim();
    if (published !== "") {
      return published;
    }
  } catch {
    // Fall through to the default for an agent that has not published one.
  }

  if (process.platform === "win32") {
    const user = process.env.USERNAME ?? "default";
    return `\\\\.\\pipe\\netra-agent-${user}`;
  }
  return path.join(stateDir, "agent.sock");
}

export class AgentClient {
  private readonly stateDir: string;

  constructor(stateDir: string = agentStateDir()) {
    this.stateDir = stateDir;
  }

  /** Reads the agent's per-boot IPC token. */
  private async token(): Promise<string> {
    try {
      const raw = await fs.readFile(path.join(this.stateDir, "ipc.token"), "utf8");
      const token = raw.trim();
      if (token === "") {
        throw new Error("empty token file");
      }
      return token;
    } catch {
      // The token file is created by the agent at startup, so its absence
      // almost always means the agent is not running.
      throw new AgentUnavailableError("The NETRA agent is not running on this device.");
    }
  }

  /** Asks the agent for its current status. */
  async status(): Promise<AgentStatus> {
    return this.call<AgentStatus>("status", {});
  }

  /**
   * Asks the agent to attest this device for a sign-in.
   *
   * Only the nonce and subject are sent: the message that gets signed is built
   * inside the agent.
   */
  async attest(nonce: string, subject: string): Promise<Attestation> {
    return this.call<Attestation>("attest", { nonce, subject });
  }

  /** Sends one request and reads one newline-delimited response. */
  private async call<T>(method: string, params: Record<string, string>): Promise<T> {
    const token = await this.token();
    const endpoint = await agentEndpoint(this.stateDir);
    const payload = `${JSON.stringify({ token, method, params })}\n`;

    const raw = await new Promise<string>((resolve, reject) => {
      const socket = net.createConnection(endpoint);
      let buffer = "";
      let settled = false;

      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        fn();
      };

      const timer = setTimeout(
        () => finish(() => reject(new AgentUnavailableError("The NETRA agent did not respond."))),
        REQUEST_TIMEOUT_MS,
      );

      socket.on("connect", () => socket.write(payload));
      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const newline = buffer.indexOf("\n");
        if (newline >= 0) {
          const line = buffer.slice(0, newline);
          finish(() => resolve(line));
        }
      });
      socket.on("error", () =>
        finish(() => reject(new AgentUnavailableError("The NETRA agent is not reachable."))),
      );
      socket.on("close", () =>
        finish(() => reject(new AgentUnavailableError("The NETRA agent closed the connection."))),
      );
    });

    let response: AgentResponse<T>;
    try {
      response = JSON.parse(raw) as AgentResponse<T>;
    } catch {
      throw new AgentUnavailableError("The NETRA agent sent an unreadable response.");
    }

    if (!response.ok || response.result === undefined) {
      throw new AgentUnavailableError(response.error ?? "The agent refused the request.");
    }
    return response.result;
  }
}
