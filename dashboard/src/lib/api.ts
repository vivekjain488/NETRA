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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { Accept: "application/json", ...init?.headers },
  });

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
