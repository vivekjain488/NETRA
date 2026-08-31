# NETRA — National Endpoint Trust, Risk & Access

A lightweight continuous-trust security platform for managed government and
defence endpoints.

Conventional access control asks *"are these credentials valid?"* once, at
login. NETRA asks a different question, continuously:

> Is this user, on this device, in this context, accessing this resource,
> behaving consistently with trusted behaviour?

It combines identity, device trust, security telemetry, behavioural baselines
and resource sensitivity into a single **explainable** risk score, and converts
that score into adaptive access decisions.

```
IDENTITY → DEVICE TRUST → TELEMETRY → BEHAVIOUR → RISK → POLICY → SOC
```

## What NETRA is not

NETRA is **not** employee surveillance. It collects security metadata only. It
does not capture keystrokes, screen contents, message bodies, camera or
microphone — and the event schema has no fields for them, so a collector cannot
report them without a schema change in review. See [docs/privacy.md](docs/privacy.md).

## Architecture

| Component | Language | Role |
|---|---|---|
| `electron/` | TypeScript + React | User-facing client: sign-in, status, launcher |
| `agent/` | Rust | Device identity, posture, telemetry, local queue |
| `backend/` | Go | Control plane: risk, policy, incidents, audit |
| `analytics/` | Python | Behavioural baselines and anomaly scoring (async) |
| `dashboard/` | TypeScript + React | SOC console |
| `demo/` | TypeScript | Sensitivity-tiered demo applications |

The Electron client is **not** the security agent, and the agent is **not** the
decision maker. Risk is computed only by the backend, from stored events — no
client can set, hint at, or lower its own score. See
[docs/architecture.md](docs/architecture.md).

## Quick start

Requires Docker, Go 1.25+, Rust 1.80+ and Node 20+.

```bash
cp .env.example .env      # adjust ports if 5432/8080 are taken on your machine
make up                   # postgres + backend + dashboard
make test                 # every test suite
```

Then:

- Backend health: <http://localhost:8080/api/v1/health>
- SOC dashboard: <http://localhost:8090>

Run the endpoint components locally:

```bash
make run-agent            # Rust agent, foreground
make run-client           # Electron client
```

## Status

Phase 1 of 16 is complete. This table is the honest state of the build; nothing
below is claimed working unless it has been run.

| Phase | Scope | Status |
|---|---|---|
| 1 | Repository, Docker stack, backend/agent/client/dashboard skeletons | **Done** |
| 2 | OIDC authentication (Keycloak), RBAC, audit | Not started |
| 3 | Device enrollment and Ed25519 device identity | Not started |
| 4 | Client ↔ agent IPC and session attestation | Not started |
| 5 | Device posture and trust score | Not started |
| 6 | Telemetry pipeline and local filtering | Not started |
| 7 | Risk engine | Not started |
| 8 | Behavioural baseline and analytics | Not started |
| 9 | Policy engine | Not started |
| 10 | SOC dashboard (full) | Skeleton only |
| 11 | Demo applications | Not started |
| 12 | Attack simulator and incident correlation | Not started |
| 13 | Hero demonstration | Not started |
| 14 | Performance benchmarks | Not started |
| 15 | Security hardening | Partially, ongoing |
| 16 | Packaging and deployment | Not started |

### Known deviation from the specification

The specification targets Windows first. Development is currently on macOS, so
telemetry collection is written against a `Collector` trait with one backend per
platform. The macOS backend is implemented and tested; the Windows backend
compiles only under `cfg(windows)` and **has not been executed on Windows
hardware**. It is marked as unverified in the source and must not be described
as working until it has been run there. See
[`agent/netra-collect/src/platform.rs`](agent/netra-collect/src/platform.rs).

## Documentation

- [Architecture](docs/architecture.md)
- [Security](docs/security.md)
- [Privacy](docs/privacy.md)
- [Threat model](docs/threat-model.md)
- [Deployment](docs/deployment.md)
- [Development](docs/development.md)
- [API](docs/api.md)
- [Demo](docs/demo.md)

## Licence

Apache-2.0. See [LICENSE](LICENSE).
