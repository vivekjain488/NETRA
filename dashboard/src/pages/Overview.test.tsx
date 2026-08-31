import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Overview } from "./Overview";

function renderOverview() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <Overview />
    </QueryClientProvider>,
  );
}

function mockHealth(body: unknown, ok = true, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok,
      status,
      json: async () => body,
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Overview", () => {
  it("renders the values the backend actually reported", async () => {
    mockHealth({
      status: "ok",
      build: { version: "0.1.0-dev", commit: "abc1234", build_time: "unknown" },
      checks: { database: "ok" },
      time: "2026-08-31T00:00:00Z",
      env: "development",
      uptime: "1m30s",
    });

    renderOverview();

    expect(await screen.findByText("ONLINE")).toBeInTheDocument();
    expect(screen.getByText("0.1.0-dev")).toBeInTheDocument();
    expect(screen.getByText("development")).toBeInTheDocument();
    expect(screen.getByText("1m30s")).toBeInTheDocument();
  });

  it("shows dependency checks from the backend", async () => {
    mockHealth({
      status: "degraded",
      build: { version: "0.1.0-dev", commit: "abc1234", build_time: "unknown" },
      checks: { database: "unavailable" },
      time: "2026-08-31T00:00:00Z",
      env: "development",
      uptime: "5s",
    });

    renderOverview();

    expect(await screen.findByText("DEGRADED")).toBeInTheDocument();
    expect(screen.getByText("unavailable")).toBeInTheDocument();
  });

  it("reports an unreachable backend instead of appearing healthy", async () => {
    // Showing a healthy console while disconnected would mislead an analyst
    // into believing there is simply nothing happening.
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    renderOverview();

    expect(await screen.findByText("Backend unreachable")).toBeInTheDocument();
    expect(screen.queryByText("ONLINE")).not.toBeInTheDocument();
  });

  it("never invents fleet figures", async () => {
    mockHealth({
      status: "ok",
      build: { version: "0.1.0-dev", commit: "abc1234", build_time: "unknown" },
      checks: { database: "ok" },
      time: "2026-08-31T00:00:00Z",
      env: "development",
      uptime: "1s",
    });

    renderOverview();

    expect(await screen.findByText("Fleet")).toBeInTheDocument();
    expect(
      screen.getByText(/No figures are shown until they are real/i),
    ).toBeInTheDocument();
  });
});
