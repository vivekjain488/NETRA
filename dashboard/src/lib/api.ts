/** Typed client for the NETRA backend API. */

export const API_BASE_URL =
  (import.meta.env.VITE_NETRA_API_URL as string | undefined) ?? "http://localhost:8080";

/** Build metadata reported by the backend. */
export interface BuildInfo {
  version: string;
  commit: string;
  build_time: string;
}

/** Response of GET /api/v1/health and /api/v1/health/ready. */
export interface HealthResponse {
  status: "ok" | "degraded";
  build: BuildInfo;
  checks: Record<string, string>;
  time: string;
  env: string;
  uptime: string;
}

/** An RFC 7807 problem detail, the shape of every backend error. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
  request_id?: string;
}

/** Error carrying the backend's problem detail and correlation id. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly problem?: Problem,
  ) {
    super(problem?.title ?? `Request failed with status ${status}`);
    this.name = "ApiError";
  }

  /** The request id, which ties this failure to a backend log line. */
  get requestId(): string | undefined {
    return this.problem?.request_id;
  }
}

// ── Domain types ────────────────────────────────────────────────────────────

export type RiskLevelName = "LOW" | "MEDIUM" | "ELEVATED" | "HIGH" | "CRITICAL";

export interface DeviceSummary {
  id: string;
  device_uid: string;
  hostname: string;
  os_name: string;
  os_version: string;
  agent_version: string;
  key_protection: string;
  state: "PENDING" | "ACTIVE" | "REVOKED";
  enrolled_at?: string;
  last_heartbeat_at?: string;
  revoked_reason?: string;
  trust_score?: number;
}

export interface PostureFactor {
  code: string;
  label: string;
  contribution: number;
  maximum: number;
  source: "verified" | "reported";
  detail?: string;
}

export interface PostureDetail {
  device_id: string;
  trust_score: number;
  factors: PostureFactor[];
  verified: boolean;
  model_version: string;
  collected_at: string;
}

export interface SessionSummary {
  id: string;
  user_id: string;
  device_id: string;
  status: "ACTIVE" | "RESTRICTED" | "ISOLATED" | "ENDED";
  attestation: string;
  current_risk?: number;
  risk_level?: string;
  started_at: string;
  last_seen_at: string;
  user_display_name?: string;
  user_email?: string;
  device_hostname?: string;
}

export interface RiskFactor {
  code: string;
  label: string;
  dimension: string;
  contribution: number;
  detail?: string;
}

export interface RiskAssessment {
  session_id: string;
  score: number;
  level: RiskLevelName;
  recommended_action: string;
  factors: RiskFactor[];
  dimensions: Record<string, number>;
  computed_at: string;
  model_version: string;
  trigger_event?: string;
}

export interface RiskDetail {
  session_id: string;
  current: RiskAssessment;
  history: Array<{
    computed_at: string;
    score: number;
    level: RiskLevelName;
    trigger?: string;
  }>;
}

export interface SecurityEvent {
  id: string;
  occurred_at: string;
  received_at: string;
  event_type: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  source: string;
  session_id?: string;
  metadata?: Record<string, string>;
  device_hostname?: string;
  user_name?: string;
}

export interface PolicySummary {
  policy_id: string;
  version: number;
  name: string;
  description?: string;
  priority: number;
  enabled: boolean;
  conditions: Record<string, unknown>;
  actions: { decision: string; create_incident?: boolean; alert_soc?: boolean; message?: string };
  fail_mode: string;
  created_at: string;
}

export interface PolicyDecision {
  id: string;
  session_id: string;
  user_name?: string;
  device_hostname?: string;
  policy_id?: string;
  policy_version?: number;
  decision: string;
  reason: string;
  evaluated_at: string;
  latency_us: number;
}

export interface IncidentSummary {
  id: string;
  incident_key: string;
  title: string;
  summary?: string;
  severity: RiskLevelName;
  status: "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";
  peak_risk: number;
  opened_at: string;
  updated_at: string;
  session_id?: string;
  user_name?: string;
  device_hostname?: string;
}

export interface IncidentDetail {
  incident: IncidentSummary;
  notes?: Array<{ id: string; author_name?: string; body: string; created_at: string }>;
  events?: SecurityEvent[];
  risk_history?: RiskAssessment[];
  decisions?: PolicyDecision[];
}

export interface Overview {
  endpoints: number;
  endpoints_trusted: number;
  endpoints_at_risk: number;
  active_sessions: number;
  high_risk_sessions: number;
  open_incidents: number;
  critical_incidents: number;
  risk_distribution: Record<string, number>;
  recent_events: SecurityEvent[];
}

export interface AuditRecord {
  seq: number;
  at: string;
  actor_type: string;
  actor_id?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  result: string;
  request_id?: string;
  detail?: Record<string, unknown>;
  hash: string;
}

export interface AuditPage {
  records: AuditRecord[];
  chain_verified: boolean;
  chain_error?: string;
}

// ── Transport ───────────────────────────────────────────────────────────────

/**
 * The analyst's bearer token.
 *
 * Held in memory only. Persisting it to localStorage would leave a working
 * credential on disk for anything that can read the browser profile.
 */
let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function hasAccessToken(): boolean {
  return accessToken !== null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });

  if (!response.ok) {
    let problem: Problem | undefined;
    try {
      problem = (await response.json()) as Problem;
    } catch {
      // A non-JSON error body is still an error; fall through with the status.
    }
    throw new ApiError(response.status, problem);
  }
  return (await response.json()) as T;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** Liveness: does not consult the database. */
export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/v1/health");
}

/**
 * Readiness: includes dependency checks.
 *
 * A degraded backend answers 503 with a valid body, which is information the
 * console needs to show rather than an error to swallow.
 */
export async function getReadiness(): Promise<HealthResponse> {
  try {
    return await request<HealthResponse>("/api/v1/health/ready");
  } catch (error) {
    if (error instanceof ApiError && error.status === 503) {
      const response = await fetch(`${API_BASE_URL}/api/v1/health/ready`);
      return (await response.json()) as HealthResponse;
    }
    throw error;
  }
}

/**
 * Signs the analyst in.
 *
 * Interactive sign-in with the organisational identity provider is not
 * implemented yet; this uses the backend's development endpoint, which exists
 * only when NETRA_ENV=development.
 */
export async function signIn(subject: string, roles: string[]): Promise<void> {
  const body = await post<{ access_token: string }>("/api/v1/dev/token", {
    subject,
    email: `${subject}@example.gov`,
    display_name: subject,
    roles,
  });
  setAccessToken(body.access_token);
}

export const api = {
  overview: () => request<Overview>("/api/v1/overview"),
  devices: () => request<{ devices: DeviceSummary[] }>("/api/v1/devices"),
  posture: (deviceId: string) => request<PostureDetail>(`/api/v1/devices/${deviceId}/posture`),
  sessions: () => request<{ sessions: SessionSummary[] }>("/api/v1/sessions"),
  risk: (sessionId: string) => request<RiskDetail>(`/api/v1/risk/${sessionId}`),
  evaluate: (sessionId: string) => post<unknown>(`/api/v1/sessions/${sessionId}/evaluate`, {}),
  events: (query = "") => request<{ events: SecurityEvent[] }>(`/api/v1/events${query}`),
  policies: () => request<{ policies: PolicySummary[] }>("/api/v1/policies"),
  decisions: () => request<{ decisions: PolicyDecision[] }>("/api/v1/policy-decisions"),
  incidents: () => request<{ incidents: IncidentSummary[] }>("/api/v1/incidents"),
  incident: (id: string) => request<IncidentDetail>(`/api/v1/incidents/${id}`),
  setIncidentStatus: (id: string, status: string) =>
    post<unknown>(`/api/v1/incidents/${id}/status`, { status }),
  audit: () => request<AuditPage>("/api/v1/audit?limit=200"),
};
