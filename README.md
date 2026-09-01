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
make env                  # creates .env, generating a random value per secret
make up                   # postgres + backend + dashboard
make test                 # every test suite
```

Adjust `NETRA_*_PORT` in `.env` if 5432 or 8080 are already taken on your
machine. To bring up Keycloak as well:

```bash
make identity-up          # adds the identity provider
make identity-passwords   # applies demo user passwords from .env
```

Then:

- Backend health: <http://localhost:8080/api/v1/health>
- SOC dashboard: <http://localhost:8090>

Run the endpoint components locally:

```bash
make run-agent            # Rust agent, foreground
make run-client           # Electron client
```

### Enrolling the agent

Enrollment is never anonymous — an administrator issues a single-use token:

```bash
# 1. Obtain an administrator token (development authentication)
ADMIN=$(curl -s -X POST http://localhost:8080/api/v1/dev/token \
  -H 'Content-Type: application/json' -d '{"subject":"priya","roles":["ADMIN"]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 2. Issue an enrollment token (returned once, stored only as a hash)
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"label":"my-laptop","ttl_minutes":30}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 3. Enrol. The agent generates its key pair and registers only the public half.
NETRA_ENROLLMENT_TOKEN="$TOKEN" make run-agent
```

The agent stores its private key locally (mode 600, or DPAPI-wrapped on
Windows) and signs every subsequent request with it. Revoking the device in the
console stops it on its very next heartbeat.

## Status

All 16 phases are complete. This table is the honest state of the build; nothing
below is claimed working unless it has been run.

| Phase | Scope | Status |
|---|---|---|
| 1 | Repository, Docker stack, backend/agent/client/dashboard skeletons | **Done** |
| 2 | OIDC authentication (Keycloak), RBAC, hash-chained audit | **Done** (interactive client sign-in pending) |
| 3 | Device enrollment and Ed25519 device identity | **Done** |
| 4 | Client ↔ agent IPC and session attestation | **Done** |
| 5 | Device posture and trust score | **Done** |
| 6 | Telemetry pipeline and local filtering | **Done** |
| 7 | Risk engine | **Done** |
| 8 | Behavioural baseline | **Done** (Python/ML layer deferred) |
| 9 | Policy engine | **Done** |
| 10 | SOC dashboard | **Done** |
| 11 | Demo applications | **Done** |
| 12 | Attack simulator and incident correlation | **Done** |
| 13 | Hero demonstration | **Done** |
| 14 | Performance benchmarks | **Done** (measured, see `bench/results.md`) |
| 15 | Security hardening | **Done** except mTLS |
| 16 | Packaging and deployment | **Done** (Windows paths untested) |

### Try the demonstration

```bash
make up
make run-agent          # in another terminal, once enrolled
```

Then open the console at <http://localhost:8090>, sign in as `ravi` /
Security analyst, and press **Demonstration → Compromised employee session**.
Risk escalates 9 → 29 → 56 → 81 → 100 across five steps, the session is
isolated and one incident opens — all through the real pipeline. See
[docs/demo.md](docs/demo.md).

### Known deviations from the specification

**Windows code is unrun.** The specification targets Windows first;
development is on macOS. Collection sits behind a `Collector` trait with one
backend per platform. The macOS backends are implemented and tested. These
compile only under `cfg(windows)` and **have not been executed on Windows
hardware** — each is marked UNVERIFIED at its definition:

- [`platform.rs`](agent/netra-collect/src/platform.rs) — hostname and OS build
- [`posture.rs`](agent/netra-collect/src/posture.rs) — BitLocker, Secure Boot, Defender
- [`activity.rs`](agent/netra-collect/src/activity.rs) — process and network sampling
- [`keystore.rs`](agent/netra-core/src/keystore.rs) — DPAPI key protection
- [`service.rs`](agent/netra-agent/src/service.rs) — Service Control Manager integration
- [`install-windows-service.ps1`](deployment/agent/install-windows-service.ps1)

**Interactive sign-in is not built.** The backend validates OIDC tokens and the
Keycloak realm is defined, but neither client performs the authorization-code
exchange. Both use the backend's development token endpoint, which exists only
when `NETRA_ENV=development`. Everything after that step — nonce, attestation,
binding, session — is the real mechanism.

**mTLS is designed, not implemented.** Agent requests are Ed25519-signed with
replay protection, which is the property that matters; mutual TLS would add
transport-level binding on top.

**Baselines are statistical, not learned.** Z-scores, histograms and frequency
sets in Go, computed in the fast path. The risk engine accepts a bounded
anomaly input for a future model, capped so it can never drive a session to
critical alone. The Python analytics service is scaffolded but not built.

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
