# Deployment

NETRA is designed to run entirely on infrastructure the operating organisation
controls. There is no dependency on any cloud provider, and no mandatory
third-party telemetry or SaaS service.

## Local stack

```bash
make env    # generates .env with a random value for every secret
make up
```

Brings up:

| Service | Image | Host port | Purpose |
|---|---|---|---|
| `postgres` | `postgres:16-alpine` | `${NETRA_POSTGRES_PORT}` | System of record |
| `backend` | built from source | `${NETRA_BACKEND_PORT}` | Control plane |
| `dashboard` | built from source, nginx | `${NETRA_DASHBOARD_PORT}` | SOC console |
Keycloak lives in a separate overlay file rather than the base stack:

```bash
make identity-up
```

An overlay is used instead of a Compose profile because Compose interpolates
the entire file regardless of which services start — a required-variable check
on Keycloak would otherwise block the base stack for anyone who has not
configured an identity provider yet.

Useful targets: `make down` (stop, keep data), `make clean` (stop and delete the
volume), `make logs`, `make ps`.

## Image construction

Both images are multi-stage:

- **Backend** — `golang:1.25-alpine` build stage, `alpine:3.21` runtime. The
  runtime layer carries no toolchain. Runs as uid 10001, never root. Version,
  commit and build time are injected via `-ldflags` and surfaced on the health
  endpoint, so a running deployment can always be traced to a source revision.
  The build mounts caches for the Go module and build directories: without
  them every image rebuild re-downloads the module set and recompiles the
  standard library, which turns a one-line change into a multi-minute wait and
  pushes developers off the documented path. With them, a source-change rebuild
  takes about three seconds.
- **Dashboard** — `node:24-alpine` build stage with `npm ci` for reproducible
  installs, `nginx:1.27-alpine` runtime with security headers and SPA routing.

Both declare healthchecks; `backend` waits on `postgres` being healthy rather
than merely started.

## Configuration

Everything comes from the environment. `NETRA_DATABASE_URL` is required and the
process refuses to start without it. Risk thresholds are validated as strictly
increasing at load, so a misconfiguration cannot silently produce a nonsensical
banding.

`POSTGRES_PASSWORD` and `KEYCLOAK_ADMIN_PASSWORD` use the Compose `:?` operator
and fail the stack rather than defaulting to a known value. `make env`
generates both, so no credential is ever committed.

## Migrations

Migrations are embedded in the backend binary, so a deployment is a single
artefact and the schema cannot drift from the code that expects it — which also
makes air-gapped deployment straightforward.

On boot the backend takes a PostgreSQL advisory lock, so concurrently starting
instances cannot migrate at the same time; each migration runs inside its own
transaction together with its bookkeeping insert, so a failure can never leave
the schema half-applied but recorded as complete.

Set `NETRA_DB_AUTO_MIGRATE=false` to apply the schema out of band instead.

## Production considerations

Not yet implemented — recorded so the gap is explicit:

- TLS termination and mTLS for the agent plane (Phase 15)
- Secrets from a managed store rather than `.env` (Phase 15)
- Backup and restore procedure for PostgreSQL
- Log shipping and retention
- Signed agent and client builds with a secure update path (Phase 16)
