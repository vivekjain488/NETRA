# Development

## Prerequisites

| Tool | Version used |
|---|---|
| Go | 1.25+ |
| Rust | 1.80+ (developed on 1.92) |
| Node.js | 20+ (developed on 24) |
| Python | 3.11+ (analytics, from Phase 8) |
| Docker | with the Compose plugin |

## Setup

```bash
make env     # creates .env, generating a random value for every blank secret
make up      # postgres + backend + dashboard
make test    # every suite
```

`.env` is gitignored, written mode 600, and must never be committed.
`.env.example` ships every secret blank on purpose.

### Authentication during development

Two options:

**Locally minted tokens** (default for tests and quick work). Set
`NETRA_DEV_AUTH_ENABLED=true` in `.env`, then:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/dev/token \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","email":"alice@example.gov","roles":["USER"]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl http://localhost:8080/api/v1/client/me -H "Authorization: Bearer $TOKEN"
```

The backend refuses this unless `NETRA_ENV=development`, and logs a loud
warning while it is on.

**Keycloak** (closer to a real deployment):

```bash
make identity-up          # starts Keycloak and imports the netra realm
make identity-passwords   # sets demo user passwords from NETRA_DEMO_PASSWORD
```

The realm defines four demo users — `alice` (USER), `ravi`
(SECURITY_ANALYST), `priya` (ADMIN), `arun` (AUDITOR) — and contains no
credentials, which is why passwords are applied as a separate step.

### Port conflicts

The published host ports are configurable, because 5432 and 8080 are commonly
already in use:

```env
NETRA_POSTGRES_PORT=5432
NETRA_BACKEND_PORT=8080
NETRA_DASHBOARD_PORT=8090
NETRA_KEYCLOAK_PORT=8081
```

If you change `NETRA_BACKEND_PORT`, also set `NETRA_PUBLIC_API_URL` to match —
it is baked into the dashboard image at build time — and rebuild:
`docker compose ... build dashboard`.

## Layout

```
backend/     Go control plane
  cmd/netrad          entrypoint
  internal/config     environment configuration, validated at load
  internal/logging    structured JSON logging, request-scoped
  internal/httpapi    router, middleware, RFC 7807 errors, health
  internal/store      pgx pool, embedded forward-only migrator
  migrations/         SQL, embedded into the binary
agent/       Rust workspace
  netra-core          config, event model, bounded queue
  netra-collect       Collector trait and platform backends
  netra-agent         service binary
electron/    Endpoint client
  main/               main process, security, IPC handlers
  preload/            the only bridge to the renderer
  renderer/           React UI
  shared/             the IPC contract, shared by both sides
dashboard/   SOC console (React + TypeScript + Tailwind + shadcn)
deployment/  Dockerfiles and Compose stack
```

## Running components individually

```bash
make run-agent     # Rust agent in the foreground, JSON logs to stdout
make run-client    # build and launch the Electron client
cd dashboard && npm run dev    # dashboard with hot reload on :5173
```

### Gotcha: `ELECTRON_RUN_AS_NODE`

If you launch the client from a terminal inside VS Code, `ELECTRON_RUN_AS_NODE=1`
is inherited from the editor and Electron starts as plain Node — `require("electron")`
then returns a path string and the app fails with
`Cannot read properties of undefined (reading 'requestSingleInstanceLock')`.
Clear it:

```bash
env -u ELECTRON_RUN_AS_NODE -u ELECTRON_NO_ATTACH_CONSOLE npm run start
```

## Enrolling the agent

```bash
ADMIN=$(curl -s -X POST http://localhost:8080/api/v1/dev/token \
  -H 'Content-Type: application/json' -d '{"subject":"priya","roles":["ADMIN"]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"label":"my-laptop","ttl_minutes":30}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

NETRA_ENROLLMENT_TOKEN="$TOKEN" make run-agent
```

Agent state lives in `NETRA_AGENT_STATE_DIR`, or by default:

| Platform | Location |
|---|---|
| Windows | `%LOCALAPPDATA%\NETRA` |
| macOS | `~/Library/Application Support/NETRA` |
| Other | `~/.netra` |

It holds `device.key` (mode 600 on Unix; DPAPI-wrapped as `device.key.dpapi` on
Windows) and `registration.json`. Deleting both makes the agent enrol again,
which needs a fresh enrollment token.

To re-enrol during development, revoke the old device first — a duplicate
`device_uid` is rejected, and a genuine reinstall generates a new one anyway.

## Testing

```bash
make test              # everything
make test-backend      # go vet + go test
make test-agent        # cargo test
make test-dashboard    # tsc --noEmit + vitest
make audit             # npm audit across both Node projects
```

Security-relevant logic is tested, not merely written: configuration
validation, DSN redaction, request-ID handling, CORS origin enforcement, panic
containment, queue bounds, and risk banding all have tests.

## Conventions

- Every value that could differ between environments comes from the environment.
- Errors are handled explicitly; nothing is silently discarded.
- Comments explain *why*, particularly for security decisions. They do not
  restate what the code says.
- A non-obvious security decision gets a comment naming the attack it prevents.
- Nothing is described as working until it has been run.
