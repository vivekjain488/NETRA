/**
 * Sign-in orchestration.
 *
 * The sequence that binds a session to both a verified user and a verified
 * device:
 *
 *   1. obtain a user token
 *   2. ask the backend for an attestation nonce
 *   3. ask the agent to sign it — the private key never leaves the agent
 *   4. present token, device identifier, nonce and signature together
 *
 * The access token is held here, in the main process, and is never passed to
 * the renderer. A renderer compromised by XSS therefore cannot exfiltrate it.
 */

import { AgentClient, AgentUnavailableError } from "./agent";

/** A session as reported by the backend. */
export interface SessionInfo {
  id: string;
  status: string;
  attestation: string;
  device_uid?: string;
  started_at: string;
  current_risk?: number;
  risk_level?: string;
}

/** Raised when sign-in cannot complete. */
export class SignInError extends Error {
  constructor(
    message: string,
    readonly cause?: string,
  ) {
    super(message);
    this.name = "SignInError";
  }
}

interface NonceResponse {
  nonce: string;
  expires_at: string;
  message: string;
}

export class SessionManager {
  /** Held only in main-process memory; never written to disk or exposed. */
  private accessToken: string | null = null;
  private subject: string | null = null;
  private session: SessionInfo | null = null;

  constructor(
    private readonly backendUrl: string,
    private readonly agent: AgentClient,
  ) {}

  /** The current session, if signed in. */
  current(): SessionInfo | null {
    return this.session;
  }

  /** The signed-in subject, if any. */
  currentSubject(): string | null {
    return this.subject;
  }

  /**
   * Signs in and establishes an attested session.
   *
   * Interactive OIDC sign-in with the organisational identity provider is not
   * implemented yet; this uses the backend's development token endpoint, which
   * exists only when NETRA_ENV=development. When that endpoint is absent the
   * error says so rather than failing obscurely.
   */
  async signIn(subject: string): Promise<SessionInfo> {
    const token = await this.developmentToken(subject);

    let nonce: NonceResponse;
    try {
      nonce = await this.post<NonceResponse>("/api/v1/client/session/nonce", token, {});
    } catch (error) {
      throw new SignInError("Could not obtain an attestation challenge.", describe(error));
    }

    let attestation;
    try {
      attestation = await this.agent.attest(nonce.nonce, subject);
    } catch (error) {
      if (error instanceof AgentUnavailableError) {
        throw new SignInError(
          "This device could not be attested because the NETRA agent is unavailable.",
          error.message,
        );
      }
      throw new SignInError("This device could not be attested.", describe(error));
    }

    let session: SessionInfo;
    try {
      session = await this.post<SessionInfo>("/api/v1/client/session/begin", token, {
        device_uid: attestation.device_uid,
        nonce: nonce.nonce,
        signature: attestation.signature,
      });
    } catch (error) {
      throw new SignInError("The control plane refused this session.", describe(error));
    }

    this.accessToken = token;
    this.subject = subject;
    this.session = session;
    return session;
  }

  /** Ends the current session and forgets the token. */
  async signOut(): Promise<void> {
    if (this.accessToken && this.session) {
      try {
        await this.post("/api/v1/client/session/end", this.accessToken, {
          session_id: this.session.id,
        });
      } catch {
        // The local state is cleared regardless: a user who asked to sign out
        // must not be left holding a token because the network failed.
      }
    }
    this.accessToken = null;
    this.subject = null;
    this.session = null;
  }

  private async developmentToken(subject: string): Promise<string> {
    const response = await fetch(`${this.backendUrl}/api/v1/dev/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, email: `${subject}@example.gov`, roles: ["USER"] }),
    });

    if (response.status === 404) {
      throw new SignInError(
        "Interactive sign-in is not implemented yet, and this backend does not offer development authentication.",
      );
    }
    if (!response.ok) {
      throw new SignInError("Could not obtain a user token.", `status ${response.status}`);
    }
    const body = (await response.json()) as { access_token?: string };
    if (!body.access_token) {
      throw new SignInError("The token response did not contain a token.");
    }
    return body.access_token;
  }

  private async post<T>(path: string, token: string, body: unknown): Promise<T> {
    const response = await fetch(`${this.backendUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const problem = (await response.json().catch(() => null)) as { detail?: string } | null;
      throw new Error(problem?.detail ?? `status ${response.status}`);
    }
    return (await response.json()) as T;
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
