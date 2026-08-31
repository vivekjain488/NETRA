# Cross-component tests

Unit tests live with the code they cover:

| Suite | Location | Command |
|---|---|---|
| Go | `backend/internal/**/*_test.go` | `make test-backend` |
| Rust | `agent/*/src/**` (`#[cfg(test)]`) | `make test-agent` |
| Dashboard | `dashboard/src/**/*.test.ts(x)` | `make test-dashboard` |

This directory holds tests that span components:

- `integration/` — agent → backend → database, risk → policy, policy → API.
  Added from Phase 3, once there is a real request to make.
- `e2e/` — Playwright, driving the SOC console and the Electron client through
  the full scenario: normal login → normal activity → anomaly → risk increase →
  policy action → SOC incident. Added in Phase 13.

Nothing is placed here before there is something real to exercise.
