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
cp .env.example .env
make up
make test
```

`.env` is gitignored and must never be committed. `.env.example` contains no
real credentials.

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
